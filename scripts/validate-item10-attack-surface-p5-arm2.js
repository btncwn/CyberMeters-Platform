#!/usr/bin/env node

import fs from "node:fs";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";
import { pathToFileURL } from "node:url";

const ROOT = path.resolve(import.meta.dirname, "..");
const NOW = "2026-08-07T10:00:00.000Z";
const modulePath = path.join(
  ROOT,
  "workers/scan-api/src/engines/asset-lifecycle-event-support.js",
);
const supportModuleUrl = process.env.ITEM10_P5_ARM2_SUPPORT_MODULE_URL ||
  pathToFileURL(modulePath).href;
const timelineModuleUrl = process.env.ITEM10_P5_ARM2_TIMELINE_MODULE_URL ||
  pathToFileURL(path.join(
    ROOT,
    "workers/scan-api/src/engines/timeline-trust.js",
  )).href;
const sourcePath = (envName, relative) =>
  process.env[envName] || path.join(ROOT, relative);
const source = (envName, relative) =>
  fs.readFileSync(sourcePath(envName, relative), "utf8");

let passed = 0;
let total = 0;
const failures = [];

function ok(name, condition, detail = "") {
  total += 1;
  if (condition) {
    passed += 1;
    console.log(`PASS ${name}`);
    return;
  }
  failures.push(name);
  console.error(`FAIL ${name}${detail ? `: ${detail}` : ""}`);
}

function eq(name, actual, expected) {
  ok(name, JSON.stringify(actual) === JSON.stringify(expected),
    `expected=${JSON.stringify(expected)} actual=${JSON.stringify(actual)}`);
}

let support = null;
let timelineTrust = null;
try {
  support = await import(`${supportModuleUrl}?arm2=${Date.now()}`);
} catch {
  support = null;
}
try {
  timelineTrust = await import(`${timelineModuleUrl}?arm2=${Date.now()}`);
} catch {
  timelineTrust = null;
}

const requiredExports = [
  "ASSET_LIFECYCLE_SUPPORT_PROJECTION_VERSION",
  "ASSET_LIFECYCLE_REPLAY_ORDER_VERSION",
  "ASSET_LIFECYCLE_TIMESTAMP_VERSION",
  "ASSET_LIFECYCLE_SUPPORT_REASON_CODES",
  "ASSET_LIFECYCLE_SUPPORT_LIMITATION_CODES",
  "normalizeLifecycleTimestamp",
  "compareLifecycleObservationOrder",
  "isDecisionRelevantLifecycleObservation",
  "evaluateAssetLifecycleEventSupport",
  "projectAssetLifecycleEventForCustomer",
  "summariseLifecycleClaimProjection",
  "loadAssetLifecycleEventSupport",
];

for (const name of requiredExports) {
  ok(`shared helper exports ${name}`, Boolean(support?.[name]));
}

if (support) {
  eq("projection version is frozen",
    support.ASSET_LIFECYCLE_SUPPORT_PROJECTION_VERSION,
    "asset-lifecycle-claim-projection-v1");
  eq("ordering version is frozen",
    support.ASSET_LIFECYCLE_REPLAY_ORDER_VERSION,
    "asset-lifecycle-replay-order-v1");
  eq("timestamp version is frozen",
    support.ASSET_LIFECYCLE_TIMESTAMP_VERSION,
    "asset-lifecycle-timestamp-v1");

  const ts = support.normalizeLifecycleTimestamp;
  const sqlite = ts("2026-08-03 10:00:01.000");
  const zoned = ts("2026-08-03T11:00:01.000+01:00");
  ok("SQLite space timestamp is accepted as UTC", sqlite.valid === true);
  eq("SQLite UTC and equivalent zoned ISO share epoch", sqlite.epoch_ms, zoned.epoch_ms);
  eq("SQLite timestamp canonicalises to UTC", sqlite.canonical_utc, "2026-08-03T10:00:01.000Z");
  const timestampDb = new DatabaseSync(":memory:");
  const sqlEpoch = (value) => Number(timestampDb.prepare(
    "SELECT ROUND((julianday(?) - 2440587.5) * 86400000) AS epoch_ms",
  ).get(value)?.epoch_ms);
  eq("sqlite_space_timestamp_is_utc_across_sql_worker_node",
    sqlEpoch("2026-08-03 10:00:01.000"), sqlite.epoch_ms);
  eq("zoned_timestamp_epoch_matches_sql_and_worker",
    sqlEpoch("2026-08-03T11:00:01.000+01:00"), zoned.epoch_ms);
  timestampDb.close();
  for (const invalid of [
    "2026-02-30 10:00:00",
    "2026-08-03 24:00:00",
    "2026-08-03T10:00:60Z",
    "2026-08-03T10:00:00+14:01",
    " 2026-08-03 10:00:00",
    "2026-08-03T10:00:00",
    "2026/08/03 10:00:00",
    "2026-08-03 10:00:00.1",
  ]) {
    ok(`timestamp rejects ${JSON.stringify(invalid)}`, ts(invalid).valid === false);
  }

  const policy = "asset-removal-confirmation-v1";
  const detail = JSON.stringify({
    active_sources: ["dns_resolution", "http_https_service"],
    passive_sources: [],
    dns_resolution: { state: "absent" },
    http_https_service: { state: "absent" },
  });
  const row = (scan_id, observed_at, overrides = {}) => ({
    asset_id: "asset-1",
    scan_id,
    observation_state: "not_observed",
    dns_state: "absent",
    http_state: "absent",
    qualifies_removal: 1,
    policy_version: policy,
    source_detail_json: detail,
    observed_at,
    created_at: observed_at.replace("T", " ").replace(".000Z", ".000"),
    ...overrides,
  });
  const event = (id, scan_id, event_type, overrides = {}) => ({
    id,
    workspace_id: "ws-1",
    asset_id: "asset-1",
    scan_id,
    event_type,
    hostname: "asset.example.com",
    created_at: NOW,
    ...overrides,
  });

  const neutral = (scan_id, observed_at) => row(scan_id, observed_at, {
    observation_state: "observation_incomplete",
    dns_state: "incomplete",
    http_state: "incomplete",
    qualifies_removal: 0,
  });
  const removalRows = [
    row("scan-n1", "2026-08-01T10:00:00.000Z"),
    row("scan-n2", "2026-08-02T10:00:00.000Z"),
    neutral("scan-neutral-1", "2026-08-03T10:00:00.000Z"),
    neutral("scan-neutral-2", "2026-08-04T10:00:00.000Z"),
    neutral("scan-neutral-3", "2026-08-05T10:00:00.000Z"),
    neutral("scan-neutral-4", "2026-08-06T10:00:00.000Z"),
    row("scan-n3", NOW),
  ];
  const removal = support.evaluateAssetLifecycleEventSupport({
    event: event("evt-removal", "scan-n3", "asset_no_longer_seen"),
    observations: removalRows,
  });
  eq("physical_recency_cannot_replace_decision_relevant_window", removal.state, "supported");
  eq("neutral physical rows cannot suppress supported removal", removal.state, "supported");
  eq("supported removal retains frozen right reason", removal.reason_code, "eligible_confirmed_removal");

  const observedTarget = row("scan-observed", "2026-08-08T10:00:00.000Z", {
    observation_state: "observed",
    dns_state: "observed",
    http_state: "observed",
    qualifies_removal: 0,
  });
  const reappearance = support.evaluateAssetLifecycleEventSupport({
    event: event("evt-reappeared", "scan-observed", "asset_reappeared"),
    observations: [...removalRows, observedTarget],
  });
  eq("neutral physical rows cannot suppress supported reappearance", reappearance.state, "supported");
  eq("supported reappearance retains frozen right reason", reappearance.reason_code,
    "eligible_reappearance_after_confirmed_removal");

  const future = row("scan-future", "2026-08-09T10:00:00.000Z", {
    observation_state: "observed",
    dns_state: "observed",
    http_state: "observed",
    qualifies_removal: 0,
  });
  const historical = support.evaluateAssetLifecycleEventSupport({
    event: event("evt-historical", "scan-n3", "asset_no_longer_seen"),
    observations: [...removalRows, future],
  });
  eq("future rows cannot change historical support", historical.state, "supported");
  eq("future_row_is_excluded_from_event_relative_window", historical.reason_code,
    "eligible_confirmed_removal");

  const uncertainCases = [
    ["null asset is uncertain", event("evt-null-asset", "scan-n3", "asset_no_longer_seen", { asset_id: null }), removalRows, "asset_identity_not_recorded"],
    ["null scan is uncertain", event("evt-null-scan", null, "asset_no_longer_seen"), removalRows, "event_scan_not_recorded"],
    ["missing exact anchor is uncertain", event("evt-missing", "scan-missing", "asset_no_longer_seen"), removalRows, "exact_lifecycle_anchor_absent"],
    ["unknown policy is uncertain", event("evt-policy", "scan-n3", "asset_no_longer_seen"), removalRows.map((r) => r.scan_id === "scan-n3" ? { ...r, policy_version: "future-v9" } : r), "unknown_policy_version"],
    ["malformed source detail is uncertain", event("evt-json", "scan-n3", "asset_no_longer_seen"), removalRows.map((r) => r.scan_id === "scan-n3" ? { ...r, source_detail_json: "{" } : r), "malformed_source_detail"],
    ["invalid relevant timestamp is uncertain", event("evt-time", "scan-n3", "asset_no_longer_seen"), removalRows.map((r) => r.scan_id === "scan-n3" ? { ...r, created_at: "2026-02-30 10:00:00" } : r), "invalid_relevant_timestamp"],
  ];
  for (const [name, candidateEvent, observations, limitation] of uncertainCases) {
    const result = support.evaluateAssetLifecycleEventSupport({ event: candidateEvent, observations });
    eq(name, result.state, "uncertain");
    eq(`${name} exposes exact limitation`, result.limitation, limitation);
    eq(`${name} never invents boolean evidence`, result.evidence_backed, null);
  }
  const missingRequiredSource = support.evaluateAssetLifecycleEventSupport({
    event: event("evt-source-shape", "scan-n3", "asset_no_longer_seen"),
    observations: removalRows.map((candidate) => candidate.scan_id === "scan-n3"
      ? {
          ...candidate,
          source_detail_json: JSON.stringify({
            active_sources: ["dns_resolution"],
            dns_resolution: { state: "absent" },
            http_https_service: { state: "absent" },
          }),
        }
      : candidate),
  });
  eq("interpretable_missing_required_source_is_unsupported",
    missingRequiredSource.state, "unsupported");
  const hostnameOnlyEvidence = removalRows.map((candidate) => ({
    ...candidate,
    asset_id: "different-asset",
    hostname: "asset.example.com",
  }));
  const hostnameFallback = support.evaluateAssetLifecycleEventSupport({
    event: event("evt-hostname-fallback", "scan-n3", "asset_no_longer_seen"),
    observations: hostnameOnlyEvidence,
  });
  eq("hostname_fallback_cannot_borrow_evidence", hostnameFallback.state, "uncertain");
  eq("hostname_fallback_reports_exact_anchor_absence", hostnameFallback.limitation,
    "exact_lifecycle_anchor_absent");

  const replayTruncatedClaim = support.evaluateAssetLifecycleEventSupport({
    event: event("evt-replay-truncated", "scan-n3", "asset_no_longer_seen"),
    observations: removalRows,
    replayComplete: false,
  });
  eq("per_event_replay_truncation_is_uncertain", replayTruncatedClaim.state, "uncertain");
  eq("per_event_replay_truncation_has_frozen_reason",
    replayTruncatedClaim.reason_code, "withheld_lifecycle_replay_truncated");
  eq("per_event_replay_truncation_has_frozen_limitation",
    replayTruncatedClaim.limitation, "bounded_relevant_replay_truncated");

  const replayAndTimestamp = support.evaluateAssetLifecycleEventSupport({
    event: event("evt-replay-time", "scan-n3", "asset_no_longer_seen"),
    observations: removalRows.map((r) => r.scan_id === "scan-n3"
      ? { ...r, created_at: "2026-02-30 10:00:00" } : r),
    replayComplete: false,
  });
  eq("replay truncation precedes invalid timestamp", replayAndTimestamp.reason_code,
    "withheld_lifecycle_replay_truncated");
  eq("replay and timestamp retain both limitations", JSON.stringify(replayAndTimestamp.limitation_codes),
    JSON.stringify(["bounded_relevant_replay_truncated", "invalid_relevant_timestamp"]));

  const policyAndDetail = support.evaluateAssetLifecycleEventSupport({
    event: event("evt-policy-detail", "scan-n3", "asset_no_longer_seen"),
    observations: removalRows.map((r) => r.scan_id === "scan-n3"
      ? { ...r, policy_version: "future-v9", source_detail_json: "{" } : r),
  });
  eq("unknown policy precedes malformed source", policyAndDetail.reason_code,
    "withheld_lifecycle_policy_unknown");
  eq("policy and source retain both limitations", JSON.stringify(policyAndDetail.limitation_codes),
    JSON.stringify(["unknown_policy_version", "malformed_source_detail"]));

  const mixedRows = [
    row("scan-n1", "2026-08-01T10:00:00.000Z", { created_at: "2026-08-01 10:00:01" }),
    row("scan-n2", "2026-08-02T10:00:00.000Z", { created_at: "2026-08-02T11:00:01.000+01:00" }),
    row("scan-z-negative", "2026-08-03T10:00:00.000Z", { created_at: "2026-08-03T10:00:00.500Z" }),
    row("scan-a-observed", "2026-08-03T10:00:00.000Z", {
      created_at: "2026-08-03 10:00:01.000",
      observation_state: "observed",
      dns_state: "observed",
      http_state: "observed",
      qualifies_removal: 0,
    }),
  ];
  const mixed = support.evaluateAssetLifecycleEventSupport({
    event: event("evt-mixed", "scan-a-observed", "asset_reappeared"),
    observations: mixedRows,
  });
  eq("mixed-format replay preserves supported reappearance", mixed.state, "supported");
  eq("mixed_format_replay_preserves_supported_reappearance", mixed.reason_code,
    "eligible_reappearance_after_confirmed_removal");

  const scanIdTieRows = [
    row("scan-n1", "2026-08-01T10:00:00.000Z"),
    row("scan-n2", "2026-08-02T10:00:00.000Z"),
    row("scan-a-negative", "2026-08-03T10:00:00.000Z", {
      created_at: "2026-08-03 10:00:01.000",
    }),
    row("scan-z-observed", "2026-08-03T10:00:00.000Z", {
      created_at: "2026-08-03 10:00:01.000",
      observation_state: "observed",
      dns_state: "observed",
      http_state: "observed",
      qualifies_removal: 0,
    }),
  ];
  const scanIdTie = support.evaluateAssetLifecycleEventSupport({
    event: event("evt-scan-id-tie", "scan-z-observed", "asset_reappeared"),
    observations: scanIdTieRows,
  });
  eq("bytewise_scan_id_tiebreak_preserves_supported_reappearance",
    scanIdTie.state, "supported");

  const claims = new Map([
    ["evt-supported-r", { state: "supported", event_type: "asset_reappeared" }],
    ["evt-supported-n", { state: "supported", event_type: "asset_no_longer_seen" }],
    ["evt-unsupported", { state: "unsupported", event_type: "asset_no_longer_seen" }],
    ["evt-uncertain", { state: "uncertain", event_type: "asset_no_longer_seen" }],
  ]);
  const projectedEvents = [
    event("evt-supported-r", "s1", "asset_reappeared"),
    event("evt-supported-n", "s2", "asset_no_longer_seen"),
    event("evt-unsupported", "s3", "asset_no_longer_seen"),
    event("evt-uncertain", "s4", "asset_no_longer_seen"),
    event("evt-new-1", "s5", "new_asset_discovered"),
    event("evt-new-2", "s6", "new_asset_discovered"),
  ];
  const summary = support.summariseLifecycleClaimProjection(projectedEvents, {
    coverage: "complete",
    scope: "validator",
    claims_by_event_id: claims,
  });
  eq("count partition total is exact", summary.total, 6);
  eq("count partition supported is exact", summary.supported, 2);
  eq("count partition unsupported is exact", summary.unsupported, 1);
  eq("count partition uncertain is exact", summary.uncertain, 1);
  eq("count partition non-lifecycle is exact", summary.non_lifecycle, 2);
  eq("removal-only supported count excludes supported reappearance",
    summary.by_event_type.asset_no_longer_seen.supported, 1);
  eq("summary_no_longer_observed_count_excludes_supported_reappearance",
    summary.by_event_type.asset_no_longer_seen.supported, 1);
  eq("reappearance bucket is separate",
    summary.by_event_type.asset_reappeared.supported, 1);
  const reappearanceOnly = support.summariseLifecycleClaimProjection(
    [event("evt-supported-r", "s1", "asset_reappeared")],
    {
      coverage: "complete",
      scope: "reappearance-only",
      claims_by_event_id: new Map([
        ["evt-supported-r", { state: "supported", event_type: "asset_reappeared" }],
      ]),
    },
  );
  eq("removal_type_is_omitted_when_out_of_scope",
    Object.hasOwn(reappearanceOnly.by_event_type, "asset_no_longer_seen"), false);

  const replayTruncatedSummary = support.summariseLifecycleClaimProjection(
    [event("evt-replay-truncated", "scan-n3", "asset_no_longer_seen")],
    {
      coverage: "complete",
      scope: "per-event-replay-truncated",
      claims_by_event_id: new Map([["evt-replay-truncated", replayTruncatedClaim]]),
    },
  );
  eq("per_event_replay_truncation_keeps_collection_complete",
    replayTruncatedSummary.coverage, "complete");
  eq("per_event_replay_truncation_is_exactly_counted_uncertain",
    replayTruncatedSummary.uncertain, 1);
  eq("per_event_replay_truncation_keeps_supported_removal_zero",
    replayTruncatedSummary.by_event_type.asset_no_longer_seen.supported, 0);

  const incomplete = support.summariseLifecycleClaimProjection(projectedEvents, {
    coverage: "truncated",
    coverage_reason: "collection_limit_exceeded",
    scope: "validator",
    claims_by_event_id: claims,
  });
  for (const field of ["total", "supported", "unsupported", "uncertain", "non_lifecycle", "customer_change_count"]) {
    eq(`truncated collection nulls ${field}`, incomplete[field], null);
  }

  const projectedUnsupported = support.projectAssetLifecycleEventForCustomer(
    event("evt-wording", "s3", "asset_no_longer_seen", { description: "Asset was removed" }),
    { state: "unsupported", evidence_backed: false, reason_code: "withheld_removal_confirmation_not_satisfied" },
  );
  eq("projector preserves raw description additively", projectedUnsupported.recorded_description, "Asset was removed");
  ok("projector replaces assertive unsupported description",
    !/was removed/i.test(projectedUnsupported.description));

  const d1FromSqlite = (database, onRead = () => {}) => ({
    prepare(sql) {
      return {
        bind(...bindings) {
          return {
            async all() {
              onRead(sql, bindings);
              return { results: database.prepare(sql).all(...bindings) };
            },
          };
        },
      };
    },
  });
  const loaderDb = new DatabaseSync(":memory:");
  loaderDb.exec(`
    CREATE TABLE asset_lifecycle_observations (
      id TEXT PRIMARY KEY,
      workspace_id TEXT NOT NULL,
      domain_id TEXT NOT NULL,
      asset_id TEXT NOT NULL,
      scan_id TEXT NOT NULL,
      hostname TEXT,
      observation_state TEXT NOT NULL,
      dns_state TEXT NOT NULL,
      http_state TEXT NOT NULL,
      qualifies_removal INTEGER NOT NULL,
      policy_version TEXT NOT NULL,
      source_detail_json TEXT,
      observed_at TEXT NOT NULL,
      created_at TEXT NOT NULL,
      UNIQUE(workspace_id, asset_id, scan_id)
    );
  `);
  const insertObservation = loaderDb.prepare(`
    INSERT INTO asset_lifecycle_observations
      (id, workspace_id, domain_id, asset_id, scan_id, hostname,
       observation_state, dns_state, http_state, qualifies_removal,
       policy_version, source_detail_json, observed_at, created_at)
    VALUES (?, 'ws-1', 'domain-1', ?, ?, 'asset.example.com', ?, ?, ?, ?, ?, ?, ?, ?)
  `);
  for (const [index, candidate] of removalRows.entries()) {
    insertObservation.run(
      `observation-${index}`,
      candidate.asset_id,
      candidate.scan_id,
      candidate.observation_state,
      candidate.dns_state,
      candidate.http_state,
      candidate.qualifies_removal,
      candidate.policy_version,
      candidate.source_detail_json,
      candidate.observed_at,
      candidate.created_at,
    );
  }
  let loaderReads = 0;
  const loadedProjection = await support.loadAssetLifecycleEventSupport(
    { cybermeters_db: d1FromSqlite(loaderDb, () => { loaderReads += 1; }) },
    {
      workspaceId: "ws-1",
      events: [event("evt-loaded", "scan-n3", "asset_no_longer_seen")],
      scope: "loader-validator",
    },
  );
  eq("loader_exact_anchor_and_relevant_replay_support_removal",
    loadedProjection.claims_by_event_id.get("evt-loaded")?.state, "supported");
  eq("loader_batches_one_event_without_n_plus_one", loaderReads, 1);

  const foreignProjection = await support.loadAssetLifecycleEventSupport(
    { cybermeters_db: d1FromSqlite(loaderDb, () => { loaderReads += 1; }) },
    {
      workspaceId: "ws-1",
      events: [event("evt-foreign", "scan-n3", "asset_no_longer_seen", {
        workspace_id: "ws-2",
      })],
      scope: "workspace-mismatch",
    },
  );
  eq("workspace_scope_mismatch_fails_collection_closed",
    foreignProjection.coverage, "unavailable");
  eq("workspace_scope_mismatch_has_frozen_reason",
    foreignProjection.coverage_reason, "workspace_scope_mismatch");

  const collectionTruncated = await support.loadAssetLifecycleEventSupport(
    { cybermeters_db: d1FromSqlite(loaderDb) },
    {
      workspaceId: "ws-1",
      events: [
        event("evt-over-1", "scan-n3", "asset_no_longer_seen"),
        event("evt-over-2", "scan-n3", "asset_no_longer_seen"),
      ],
      collectionLimit: 1,
      scope: "collection-bound",
    },
  );
  eq("collection_bound_returns_truncated_coverage",
    collectionTruncated.coverage, "truncated");
  const collectionTruncatedSummary = support.summariseLifecycleClaimProjection(
    [
      event("evt-over-1", "scan-n3", "asset_no_longer_seen"),
      event("evt-over-2", "scan-n3", "asset_no_longer_seen"),
    ],
    collectionTruncated,
  );
  eq("collection_truncation_never_publishes_partial_count",
    collectionTruncatedSummary.customer_change_count, null);

  const schemaAbsentDb = new DatabaseSync(":memory:");
  const schemaAbsent = await support.loadAssetLifecycleEventSupport(
    { cybermeters_db: d1FromSqlite(schemaAbsentDb) },
    {
      workspaceId: "ws-1",
      events: [event("evt-schema", "scan-n3", "asset_no_longer_seen")],
      scope: "schema-absent",
    },
  );
  eq("schema_absence_is_collection_unavailable", schemaAbsent.coverage, "unavailable");
  eq("schema_absence_never_becomes_honest_zero",
    support.summariseLifecycleClaimProjection(
      [event("evt-schema", "scan-n3", "asset_no_longer_seen")],
      schemaAbsent,
    ).customer_change_count, null);
  schemaAbsentDb.close();

  const readFailure = await support.loadAssetLifecycleEventSupport(
    {
      cybermeters_db: {
        prepare() {
          return {
            bind() {
              return { async all() { throw new Error("networked D1 read failed"); } };
            },
          };
        },
      },
    },
    {
      workspaceId: "ws-1",
      events: [event("evt-read", "scan-n3", "asset_no_longer_seen")],
      scope: "read-failure",
    },
  );
  eq("read_failure_is_collection_unavailable", readFailure.coverage, "unavailable");
  eq("read_failure_never_becomes_honest_zero",
    support.summariseLifecycleClaimProjection(
      [event("evt-read", "scan-n3", "asset_no_longer_seen")],
      readFailure,
    ).customer_change_count, null);
  loaderDb.close();
}

ok("timeline trust module imports", Boolean(timelineTrust?.collapseCustomerTimelineEvents));
if (timelineTrust?.collapseCustomerTimelineEvents) {
  const flipFlop = (state) => [
    {
      id: `absence-${state}`,
      event_type: "asset_no_longer_seen",
      hostname: "asset.example.com",
      created_at: NOW,
      lifecycle_claim_support: { state },
    },
    {
      id: `reappearance-${state}`,
      event_type: "asset_reappeared",
      hostname: "asset.example.com",
      created_at: "2026-08-07T11:00:00.000Z",
      lifecycle_claim_support: { state },
    },
  ];
  eq("supported_flip_flop_may_collapse",
    timelineTrust.collapseCustomerTimelineEvents(flipFlop("supported")).length, 0);
  eq("unsupported_rows_remain_visible_and_do_not_collapse",
    timelineTrust.collapseCustomerTimelineEvents(flipFlop("unsupported")).length, 2);
  eq("uncertain_rows_remain_visible_and_do_not_collapse",
    timelineTrust.collapseCustomerTimelineEvents(flipFlop("uncertain")).length, 2);
}

const migration = path.join(ROOT, "database/migrations/106-scheduled-asset-change-projection.sql");
const schema = fs.readFileSync(path.join(ROOT, "database/schema.sql"), "utf8");
const scans = fs.readFileSync(path.join(ROOT, "workers/scan-api/src/routes/scans.js"), "utf8");
ok("migration 106 exists", fs.existsSync(migration));
if (fs.existsSync(migration)) {
  const sql = fs.readFileSync(migration, "utf8");
  ok("migration 106 is additive nullable no-backfill",
    /ALTER TABLE scheduled_scans\s+ADD COLUMN asset_change_projection_json TEXT/i.test(sql) &&
    !/UPDATE\s+scheduled_scans/i.test(sql));
}
ok("canonical schema carries scheduled projection column",
  /asset_change_projection_json\s+TEXT/.test(schema));
ok("idempotent scheduled-scans bootstrap carries projection column",
  /asset_change_projection_json\s+TEXT/.test(scans));

const deliverySource = source(
  "ITEM10_P5_ARM2_DELIVERY_SOURCE",
  "workers/scan-api/src/engines/asset-alert-delivery.js",
);
const assetAlertsSource = source(
  "ITEM10_P5_ARM2_ASSET_ALERTS_SOURCE",
  "workers/scan-api/src/engines/asset-alerts.js",
);
const indexSource = source(
  "ITEM10_P5_ARM2_INDEX_SOURCE",
  "workers/scan-api/src/index.js",
);
const scansSource = source(
  "ITEM10_P5_ARM2_SCANS_SOURCE",
  "workers/scan-api/src/routes/scans.js",
);
const scheduledProjectionReaderSource = scansSource.slice(
  scansSource.indexOf("function readScheduledAssetChangeProjection"),
  scansSource.indexOf("export async function scanRoutes"),
);
const attackSurfaceSource = source(
  "ITEM10_P5_ARM2_ATTACK_SURFACE_SOURCE",
  "workers/scan-api/src/routes/attack-surface.js",
);
const frontendDisplaySource = source(
  "ITEM10_P5_ARM2_FRONTEND_DISPLAY_SOURCE",
  "frontend/src/lib/assetLifecycleClaimDisplay.js",
);
const portfolioSource = source(
  "ITEM10_P5_ARM2_PORTFOLIO_SOURCE",
  "workers/scan-api/src/routes/portfolio.js",
);
const portfolioCustomersSource = source(
  "ITEM10_P5_ARM2_PORTFOLIO_CUSTOMERS_SOURCE",
  "workers/scan-api/src/engines/portfolio-customers.js",
);
const scorecardSource = source(
  "ITEM10_P5_ARM2_SCORECARD_SOURCE",
  "workers/scan-api/src/engines/scorecard.js",
);
const weeklyDigestSource = source(
  "ITEM10_P5_ARM2_WEEKLY_DIGEST_SOURCE",
  "workers/scan-api/src/engines/weekly-digest.js",
);

ok("delivery_uses_shared_event_relative_replay",
  /const lifecycleRead = preloadedLifecycleProjection\s*\? Promise\.resolve\(preloadedLifecycleProjection\)\s*:\s*loadAssetLifecycleEventSupport\(env, \{/.test(deliverySource) &&
  /events:\s*events\.filter/.test(deliverySource) &&
  !/ORDER BY[^;]+LIMIT\s+4/is.test(deliverySource));
ok("delivery_maps_only_supported_lifecycle_claims_to_eligible",
  /claim\.state\s*===\s*"supported"/.test(assetAlertsSource) &&
  /evaluateAssetAlertEligibility\(alertEvents, evidence\)/.test(deliverySource));

eq("both_scheduled_writers_use_one_projection_writer",
  (indexSource.match(/await persistScheduledAssetChangeProjection\(env,/g) || []).length,
  2);
ok("scheduled_projection_writer_uses_exact_source_scan_and_workspace",
  (indexSource.match(/WHERE scan_id = \? AND workspace_id = \?/g) || []).length >= 2 &&
  /scan_id:\s*scanId/.test(indexSource));
ok("scheduled_projection_update_is_schedule_and_workspace_scoped",
  /WHERE id = \? AND workspace_id = \?/.test(indexSource) &&
  /\.bind\(totalResult\?\.n \?\? 0, changeCount, projectionJson, scheduleId, workspaceId\)/.test(
    indexSource,
  ));
ok("scheduled_projection_keeps_legacy_raw_count_separate",
  /asset_change_count = \?/.test(indexSource) &&
  /asset_change_projection_json = \?/.test(indexSource));
ok("schedule_null_projection_is_not_evaluated",
  /if \(typeof value !== "string" \|\| value\.length === 0\) return null;/.test(
    scansSource,
  ) && /asset_change_projection:\s*readScheduledAssetChangeProjection/.test(scansSource));
ok("schedule_null_projection_does_not_emit_honest_zero",
  !/asset_change_projection:\s*[^,]*\?\?\s*0/.test(scansSource) &&
  /if \(typeof value !== "string" \|\| value\.length === 0\) return null;/.test(
    scheduledProjectionReaderSource,
  ) &&
  !/customer_change_count:\s*0/.test(scheduledProjectionReaderSource));

ok("honest_summary_uses_supported_removal_bucket_not_legacy_raw",
  /by_event_type\?\.asset_no_longer_seen\?\.supported \?\? 0/.test(
    attackSurfaceSource,
  ) &&
  /no_longer_observed_assets_30d:\s*noLongerObservedAssets30d/.test(
    attackSurfaceSource,
  ));
ok("honest_timeline_uses_supported_removal_rows_not_legacy_raw",
  /event\.event_type === "asset_no_longer_seen"/.test(attackSurfaceSource) &&
  /event\.lifecycle_claim_support\?\.state === "supported"/.test(
    attackSurfaceSource,
  ) &&
  /no_longer_observed_assets:\s*\n\s*projected\.summary\.coverage === "complete"/.test(
    attackSurfaceSource,
  ) &&
  /projected\.summary\.coverage === "complete"\s*\n\s*\? supportedNoLongerByDay\.get\(day\) \|\| 0\s*\n\s*: null/.test(
    attackSurfaceSource,
  ));
ok("daily_no_longer_observed_count_excludes_supported_reappearance",
  /event\.event_type === "asset_no_longer_seen"/.test(attackSurfaceSource) &&
  !/supportedNoLongerByDay\.set\([^\n]*asset_reappeared/.test(attackSurfaceSource));

ok("asset_timeline_projects_before_customer_collapse",
  /buildProjectionAwareTimelineDays/.test(attackSurfaceSource) &&
  /buildProjectionAwareTimelineDays\(\s*legacyTimeline,\s*projected\.events/.test(attackSurfaceSource) &&
  /unsupported/.test(attackSurfaceSource) && /uncertain/.test(attackSurfaceSource));
ok("posture_timeline_projects_before_customer_collapse",
  /buildProjectionAwareTimelineDays/.test(attackSurfaceSource) &&
  /buildProjectionAwareTimelineDays\(\s*\[\.\.\.eventMap\.values\(\)\],\s*projected\.events/.test(attackSurfaceSource) &&
  /unsupported/.test(attackSurfaceSource) && /uncertain/.test(attackSurfaceSource));

const rawLifecyclePair = [
  { event_type: "asset_no_longer_seen", hostname: "flip.example", created_at: "2026-08-01T10:00:00Z" },
  { event_type: "asset_reappeared", hostname: "flip.example", created_at: "2026-08-01T11:00:00Z" },
];
const projectedLifecyclePair = rawLifecyclePair.map((row, i) => ({
  ...row,
  lifecycle_claim_support: { state: i ? "uncertain" : "unsupported" },
}));
eq("raw remove reappear pair collapses in the raw carrier",
  timelineTrust.collapseCustomerTimelineEvents(rawLifecyclePair).length, 0);
eq("projected unsupported uncertain pair remains visible",
  timelineTrust.collapseCustomerTimelineEvents(projectedLifecyclePair).length, 2);
eq("projected unsupported uncertain pair retains its day",
  new Set(projectedLifecyclePair.map((row) => row.created_at.slice(0, 10))).size, 1);
eq("projected unsupported uncertain pair has zero honest supported removals",
  projectedLifecyclePair.filter((row) => row.lifecycle_claim_support.state === "supported" && row.event_type === "asset_no_longer_seen").length, 0);

ok("frontend_missing_projection_is_support_not_evaluated",
  /title:\s*'Historical lifecycle record — support not evaluated'/.test(
    frontendDisplaySource,
  ) && /supportLabel:\s*'Support not evaluated'/.test(frontendDisplaySource));
ok("frontend_missing_projected_count_is_not_evaluated_not_zero",
  /return \{ value: null, label: 'Not evaluated' \}/.test(frontendDisplaySource));

eq("attack_surface_projects_all_six_audited_read_contracts",
  (attackSurfaceSource.match(/await projectLifecycleEvents\(/g) || []).length, 6);
ok("portfolio_list_projects_per_workspace_before_customer_render",
  /projectionsByWorkspace = await loadAssetLifecycleEventSupportForWorkspaces\(env, \{\s*workspaceIds: loadableWorkspaceIds,\s*events: rawPortfolioEvents,/.test(
    portfolioSource,
  ) &&
  portfolioSource.indexOf("await loadAssetLifecycleEventSupportForWorkspaces") <
    portfolioSource.indexOf("for (const workspaceId of workspaceIds)"));
ok("portfolio_alert_rows_preserve_projected_lifecycle_claim_support",
  /recorded_description:\s*r\.recorded_description \?\? null/.test(portfolioSource) &&
  /lifecycle_claim_support:\s*r\.lifecycle_claim_support \?\? null/.test(portfolioSource));
ok("portfolio_customer_and_executive_counts_use_projection",
  /customer_changes_7d/.test(portfolioCustomersSource) &&
  /lifecycle_claim_projection/.test(portfolioCustomersSource));
ok("scorecard_retains_raw_and_adds_customer_projection",
  /asset_events_30d/.test(scorecardSource) &&
  /customer_asset_events_30d/.test(scorecardSource) &&
  /lifecycle_claim_projection/.test(scorecardSource));
ok("weekly_digest_headline_is_supported_lifecycle_plus_semantic_non_lifecycle",
  /const customerChanges = projectedChanges\.filter/.test(weeklyDigestSource) &&
  /event\.lifecycle_claim_support\?\.state === "supported"/.test(weeklyDigestSource) &&
  /customer_total:\s*exactCustomerCounts \? customerChanges\.length : null/.test(
    weeklyDigestSource,
  ) &&
  /const total = hasCustomerContract \? changes\.customer_total : changes\.total/.test(
    weeklyDigestSource,
  ));
ok("weekly_digest_discloses_non_supported_lifecycle_without_all_clear",
  /const lifecycleReview = projectedChanges\.filter/.test(weeklyDigestSource) &&
  /total:\s*exactCustomerCounts \? lifecycleReview\.length : null/.test(weeklyDigestSource) &&
  /historical lifecycle record/.test(weeklyDigestSource) &&
  /could not be counted as evidence-supported changes/.test(weeklyDigestSource));

console.log(`ITEM10_P5_ARM2: ${passed}/${total} PASS`);
if (failures.length > 0) {
  console.error(`FAILED_ASSERTIONS=${JSON.stringify(failures)}`);
  process.exit(1);
}
