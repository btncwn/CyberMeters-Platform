#!/usr/bin/env node
// CT-R2 PR-2A.1 migration-105 schema/data proof. This validator builds the
// exact migration-103/104 starting contracts, seeds 124 historical CT-R1 rows,
// applies migration 105 once, and verifies content plus dependent objects.
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";
import { fileURLToPath } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const migration103Path = path.join(root, "database/migrations/103-ct-provider-telemetry.sql");
const migration104Path = path.join(root, "database/migrations/104-ct-provider-overlap-telemetry.sql");
const migration105Path = process.env.CT_PLATFORM_ABORT_MIGRATION_PATH || path.join(
  root,
  "database/migrations/105-ct-platform-deadline-provenance.sql",
);

let passed = 0;
let failed = 0;
const ok = (name, condition, detail = "") => {
  if (condition) passed += 1;
  else {
    failed += 1;
    console.error(`FAIL ${name}${detail ? ` — ${detail}` : ""}`);
  }
};
const same = (name, got, want) => ok(
  name,
  JSON.stringify(got) === JSON.stringify(want),
  `got ${JSON.stringify(got)} want ${JSON.stringify(want)}`,
);
const sha256 = (value) => crypto.createHash("sha256").update(value).digest("hex");
const normalizeSql = (value) => String(value || "").replace(/\s+/g, " ").trim().toLowerCase();

function tableColumns(db, table) {
  return db.prepare(`PRAGMA table_info(${table})`).all();
}

function rowFingerprint(db, table) {
  const columns = tableColumns(db, table).map((row) => row.name);
  const quoted = columns.map((column) => `"${column}"`).join(", ");
  const rows = db.prepare(`SELECT ${quoted} FROM ${table} ORDER BY id`).all();
  return sha256(JSON.stringify(rows));
}

function historicalSummary(db) {
  const nullable = ["http_status", "result_count", "affected_signal", "cache_age_s"];
  return {
    total: Number(db.prepare("SELECT COUNT(*) AS n FROM ct_provider_telemetry").get().n),
    fingerprint: rowFingerprint(db, "ct_provider_telemetry"),
    groups: db.prepare(
      `SELECT module, provider, outcome, COUNT(*) AS n
       FROM ct_provider_telemetry
       GROUP BY module, provider, outcome
       ORDER BY module, provider, outcome`,
    ).all(),
    ranges: db.prepare(
      `SELECT MIN(started_at) AS min_started_at, MAX(started_at) AS max_started_at,
              MIN(completed_at) AS min_completed_at, MAX(completed_at) AS max_completed_at
       FROM ct_provider_telemetry`,
    ).get(),
    nulls: Object.fromEntries(nullable.map((column) => [
      column,
      Number(db.prepare(
        `SELECT SUM(CASE WHEN "${column}" IS NULL THEN 1 ELSE 0 END) AS n
         FROM ct_provider_telemetry`,
      ).get().n),
    ])),
    duplicatePrimaryKeys: Number(db.prepare(
      `SELECT COUNT(*) - COUNT(DISTINCT id) AS n FROM ct_provider_telemetry`,
    ).get().n),
  };
}

function indexMetadata(db, table, wantedName) {
  const entry = db.prepare(`PRAGMA index_list(${table})`).all()
    .find((candidate) => candidate.name === wantedName);
  if (!entry) return null;
  return {
    unique: Number(entry.unique),
    origin: entry.origin,
    partial: Number(entry.partial),
    columns: db.prepare(`PRAGMA index_info(${wantedName})`).all().map((row) => row.name),
  };
}

function semanticPrimaryKey(db, table) {
  const id = tableColumns(db, table).find((column) => column.name === "id");
  const origin = db.prepare(`PRAGMA index_list(${table})`).all()
    .find((index) => index.origin === "pk");
  return id?.type === "TEXT" && Number(id.pk) === 1
    && origin?.unique === 1
    && JSON.stringify(db.prepare(`PRAGMA index_info(${origin.name})`).all().map((row) => row.name))
      === JSON.stringify(["id"]);
}

function semanticUnique(db, table, columns) {
  return db.prepare(`PRAGMA index_list(${table})`).all().some((index) => (
    index.origin === "u"
    && Number(index.unique) === 1
    && JSON.stringify(db.prepare(`PRAGMA index_info(${index.name})`).all().map((row) => row.name))
      === JSON.stringify(columns)
  ));
}

function foreignKeyToScans(db, table) {
  return db.prepare(`PRAGMA foreign_key_list(${table})`).all().some((row) => (
    row.table === "scans" && row.from === "scan_id" && row.to === "id"
  ));
}

function insertHistoricalRows(db) {
  const outcomes = [
    "ok", "timeout", "http_error", "parse_error", "rate_limited", "network_error",
  ];
  const insert = db.prepare(
    `INSERT INTO ct_provider_telemetry
       (id, scan_id, module, provider, outcome, http_status, latency_ms,
        result_count, started_at, completed_at, completeness_impact,
        affected_signal, cache_state, cache_age_s, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
  );
  for (let index = 0; index < 124; index += 1) {
    const outcome = outcomes[index % outcomes.length];
    const impact = index % 5 === 0 ? 1 : 0;
    const hour = String(index % 24).padStart(2, "0");
    const minute = String(index % 60).padStart(2, "0");
    insert.run(
      `ctpt-historical-${String(index).padStart(3, "0")}`,
      `scan-historical-${Math.floor(index / 8)}`,
      index % 2 === 0 ? "ssl" : "subdomains",
      index % 3 === 0 ? "certspotter" : "crt_sh",
      outcome,
      ["http_error", "rate_limited"].includes(outcome) ? (outcome === "rate_limited" ? 429 : 503) : null,
      100 + index,
      outcome === "ok" ? index % 17 : null,
      `2026-07-${String(1 + (index % 28)).padStart(2, "0")}T${hour}:${minute}:00.000Z`,
      `2026-07-${String(1 + (index % 28)).padStart(2, "0")}T${hour}:${minute}:01.000Z`,
      impact,
      impact ? (index % 2 === 0 ? "certificate_transparency" : "subdomain_discovery") : null,
      ["miss", "fresh_hit", "stale_available"][index % 3],
      index % 4 === 0 ? null : index,
      `2026-08-01T${hour}:${minute}:02.000Z`,
    );
  }
}

const PROVIDER_COUNT_SUFFIXES = [
  "attempt_state", "raw_record_count", "expanded_candidate_count",
  "normalization_input_count", "normalization_dropped_candidate_count",
  "normalization_truncated", "normalized_candidate_count", "unique_hostname_count",
  "retained_hostname_count", "dropped_hostname_count", "truncated",
];
const OVERLAP_COLUMNS = [
  "id", "scan_id", "module", "source_set_version", "observed_at",
  "normalization_candidate_limit", "retained_hostname_limit",
  ...["crt_sh", "certspotter"].flatMap((provider) =>
    PROVIDER_COUNT_SUFFIXES.map((suffix) => `${provider}_${suffix}`)),
  "comparison_status", "intersection_count", "crt_sh_only_count",
  "certspotter_only_count", "union_count", "created_at",
];

function overlapValues({ id, crtShState, certspotterState, comparisonStatus }) {
  const values = {
    id,
    scan_id: "scan-vocabulary",
    module: "subdomains",
    source_set_version: id,
    observed_at: "2026-08-02T10:00:00.000Z",
    normalization_candidate_limit: 4096,
    retained_hostname_limit: 256,
    comparison_status: comparisonStatus,
    intersection_count: comparisonStatus === "compared" ? 0 : null,
    crt_sh_only_count: comparisonStatus === "compared" ? 0 : null,
    certspotter_only_count: comparisonStatus === "compared" ? 0 : null,
    union_count: comparisonStatus === "compared" ? 0 : null,
    created_at: "2026-08-02T10:00:01.000Z",
  };
  for (const [provider, state] of [["crt_sh", crtShState], ["certspotter", certspotterState]]) {
    values[`${provider}_attempt_state`] = state;
    for (const suffix of PROVIDER_COUNT_SUFFIXES.slice(1)) {
      values[`${provider}_${suffix}`] = state === "terminal_success" ? 0 : null;
    }
  }
  return OVERLAP_COLUMNS.map((column) => values[column]);
}

function insertOverlap(db, args) {
  const placeholders = OVERLAP_COLUMNS.map(() => "?").join(", ");
  return db.prepare(
    `INSERT INTO ct_provider_overlap_telemetry
       (${OVERLAP_COLUMNS.join(", ")}) VALUES (${placeholders})`,
  ).run(...overlapValues(args));
}

const migration103 = fs.readFileSync(migration103Path, "utf8");
const migration104 = fs.readFileSync(migration104Path, "utf8");
const migration105 = fs.readFileSync(migration105Path, "utf8");
const executable105 = migration105.replace(/--[^\n]*/g, "");

ok("migration: no raw BEGIN or COMMIT",
  !/^\s*(?:BEGIN(?:\s+TRANSACTION)?|COMMIT)\s*;/im.test(executable105));
ok("migration: defers foreign keys within D1 implicit transaction",
  /PRAGMA\s+defer_foreign_keys\s*=\s*on/i.test(executable105));
ok("migration: overlap rebuild precedes CT-R1 rebuild",
  executable105.indexOf("CREATE TABLE ct_provider_overlap_telemetry__105")
    < executable105.indexOf("CREATE TABLE ct_provider_telemetry__105"));

const db = new DatabaseSync(":memory:");
db.exec("PRAGMA foreign_keys = on; CREATE TABLE scans (id TEXT PRIMARY KEY);");
for (let index = 0; index < 16; index += 1) {
  db.prepare("INSERT INTO scans (id) VALUES (?)").run(`scan-historical-${index}`);
}
db.prepare("INSERT INTO scans (id) VALUES (?)").run("scan-vocabulary");
db.prepare("INSERT INTO scans (id) VALUES (?)").run("scan-trigger-bound");
db.exec(migration103);
db.exec(migration104);
insertHistoricalRows(db);
const before = historicalSummary(db);
same("history: supplied production row count fixture is 124", before.total, 124);
same("history: pre-migration duplicate primary-key count is zero", before.duplicatePrimaryKeys, 0);
same("history: pre-migration overlap row count is zero",
  Number(db.prepare("SELECT COUNT(*) AS n FROM ct_provider_overlap_telemetry").get().n), 0);

let migrationError = null;
try {
  db.exec(migration105);
} catch (error) {
  migrationError = error;
}
ok("migration: applies successfully", migrationError === null, migrationError?.message || "");

if (migrationError === null) {
  const after = historicalSummary(db);
  same("history: total row count preserved", after.total, before.total);
  same("history: deterministic full-row fingerprint preserved", after.fingerprint, before.fingerprint);
  same("history: module/provider/outcome groups preserved", after.groups, before.groups);
  same("history: started/completed MIN/MAX preserved", after.ranges, before.ranges);
  same("history: nullable-field distributions preserved", after.nulls, before.nulls);
  same("history: duplicate primary-key count remains zero", after.duplicatePrimaryKeys, 0);

  const objects = db.prepare(
    `SELECT type, name FROM sqlite_master
     WHERE name IN ('ct_provider_telemetry', 'ct_provider_overlap_telemetry',
       'ct_provider_telemetry_105_new', 'ct_provider_overlap_telemetry_105_new')
     ORDER BY name`,
  ).all();
  same("schema: original table names are authoritative and temporary tables are absent", objects, [
    { type: "table", name: "ct_provider_overlap_telemetry" },
    { type: "table", name: "ct_provider_telemetry" },
  ]);

  same("schema: CT-R1 scan index preserved", indexMetadata(
    db, "ct_provider_telemetry", "idx_ct_provider_telemetry_scan",
  ), { unique: 0, origin: "c", partial: 0, columns: ["scan_id", "module", "provider"] });
  same("schema: CT-R1 provider/time index preserved", indexMetadata(
    db, "ct_provider_telemetry", "idx_ct_provider_telemetry_provider_time",
  ), { unique: 0, origin: "c", partial: 0, columns: ["provider", "started_at"] });
  const trigger = db.prepare(
    "SELECT sql FROM sqlite_master WHERE type = 'trigger' AND name = ?",
  ).get("trg_ct_provider_telemetry_scan_row_bound");
  ok("schema: CT-R1 row-bound trigger preserved by exact name",
    /BEFORE INSERT ON ct_provider_telemetry[\s\S]*COUNT\(\*\)[\s\S]*>= 8/i.test(trigger?.sql || ""));
  ok("schema: CT-R1 TEXT PRIMARY KEY semantic constraint preserved",
    semanticPrimaryKey(db, "ct_provider_telemetry"));
  const ctTableSql = normalizeSql(db.prepare(
    "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'ct_provider_telemetry'",
  ).get()?.sql);
  ok("schema: CT-R1 CREATE TABLE retains TEXT PRIMARY KEY contract",
    /\bid text primary key\b/.test(ctTableSql));

  same("schema: overlap scan index preserved", indexMetadata(
    db, "ct_provider_overlap_telemetry", "idx_ct_provider_overlap_telemetry_scan",
  ), { unique: 0, origin: "c", partial: 0, columns: ["scan_id", "observed_at"] });
  same("schema: overlap status/time index preserved", indexMetadata(
    db, "ct_provider_overlap_telemetry", "idx_ct_provider_overlap_telemetry_status_time",
  ), { unique: 0, origin: "c", partial: 0, columns: ["comparison_status", "observed_at"] });
  ok("schema: overlap TEXT PRIMARY KEY semantic constraint preserved",
    semanticPrimaryKey(db, "ct_provider_overlap_telemetry"));
  ok("schema: overlap UNIQUE semantic constraint preserved",
    semanticUnique(db, "ct_provider_overlap_telemetry", ["scan_id", "module", "source_set_version"]));
  const overlapTableSql = normalizeSql(db.prepare(
    "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'ct_provider_overlap_telemetry'",
  ).get()?.sql);
  ok("schema: overlap CREATE TABLE retains TEXT PRIMARY KEY contract",
    /\bid text primary key\b/.test(overlapTableSql));
  ok("schema: overlap CREATE TABLE retains UNIQUE column contract",
    /unique \(scan_id, module, source_set_version\)/.test(overlapTableSql));
  ok("schema: both scan foreign keys preserved",
    foreignKeyToScans(db, "ct_provider_telemetry")
      && foreignKeyToScans(db, "ct_provider_overlap_telemetry"));
  same("schema: foreign-key violations remain zero", db.prepare("PRAGMA foreign_key_check").all(), []);

  let triggerRejectedNinth = false;
  const triggerInsert = db.prepare(
    `INSERT INTO ct_provider_telemetry
       (id, scan_id, module, provider, outcome, latency_ms, started_at, completed_at)
     VALUES (?, 'scan-trigger-bound', 'ssl', 'crt_sh', 'network_error', 1,
       '2026-08-02T10:00:00Z', '2026-08-02T10:00:01Z')`,
  );
  try {
    for (let index = 0; index < 9; index += 1) triggerInsert.run(`ctpt-trigger-${index}`);
  } catch (error) {
    triggerRejectedNinth = /row bound exceeded/i.test(String(error?.message || error));
  }
  ok("schema: CT-R1 row-bound trigger remains effective", triggerRejectedNinth);

  let platformAttemptAccepted = true;
  try {
    db.prepare(
      `INSERT INTO ct_provider_telemetry
         (id, scan_id, module, provider, outcome, latency_ms, started_at, completed_at)
       VALUES ('ctpt-platform', 'scan-vocabulary', 'subdomains', 'crt_sh',
         'platform_deadline_abort', 9, '2026-08-02T10:00:00Z', '2026-08-02T10:00:09Z')`,
    ).run();
  } catch { platformAttemptAccepted = false; }
  ok("vocabulary: CT-R1 platform_deadline_abort is accepted", platformAttemptAccepted);

  let invalidPlatformCountsRejected = false;
  try {
    db.prepare(
      `INSERT INTO ct_provider_telemetry
         (id, scan_id, module, provider, outcome, latency_ms, result_count,
          started_at, completed_at)
       VALUES ('ctpt-platform-invalid', 'scan-vocabulary', 'subdomains', 'crt_sh',
         'platform_deadline_abort', 9, 0,
         '2026-08-02T10:00:00Z', '2026-08-02T10:00:09Z')`,
    ).run();
  } catch { invalidPlatformCountsRejected = true; }
  ok("coherence: CT-R1 platform abort cannot carry a result count", invalidPlatformCountsRejected);

  let mixedCauseAccepted = true;
  try {
    insertOverlap(db, {
      id: "ctpot-mixed-platform-provider",
      crtShState: "terminal_platform_deadline_abort",
      certspotterState: "terminal_failure",
      comparisonStatus: "censored_platform_deadline_abort",
    });
  } catch { mixedCauseAccepted = false; }
  ok("vocabulary: mixed platform/provider cause accepts platform-censored precedence", mixedCauseAccepted);

  let wrongMixedPrecedenceRejected = false;
  try {
    insertOverlap(db, {
      id: "ctpot-mixed-wrong-precedence",
      crtShState: "terminal_platform_deadline_abort",
      certspotterState: "terminal_failure",
      comparisonStatus: "censored_provider_failure",
    });
  } catch { wrongMixedPrecedenceRejected = true; }
  ok("coherence: mixed platform/provider cause rejects provider-failure precedence",
    wrongMixedPrecedenceRejected);

  const pairFixtures = [
    ["terminal_success", "terminal_success", "compared"],
    ["terminal_success", "terminal_failure", "censored_provider_failure"],
    ["terminal_success", "terminal_platform_deadline_abort", "censored_platform_deadline_abort"],
    ["terminal_success", "in_flight_at_consumer_release", "censored_in_flight"],
    ["terminal_success", "not_started", "not_started"],
    ["terminal_failure", "terminal_failure", "censored_provider_failure"],
    ["terminal_failure", "terminal_platform_deadline_abort", "censored_platform_deadline_abort"],
    ["terminal_failure", "in_flight_at_consumer_release", "censored_in_flight"],
    ["terminal_failure", "not_started", "not_started"],
    ["terminal_platform_deadline_abort", "terminal_platform_deadline_abort", "censored_platform_deadline_abort"],
    ["terminal_platform_deadline_abort", "not_started", "censored_platform_deadline_abort"],
    ["in_flight_at_consumer_release", "in_flight_at_consumer_release", "censored_in_flight"],
    ["in_flight_at_consumer_release", "not_started", "not_started"],
    ["not_started", "not_started", "not_started"],
  ];
  const pairFailures = [];
  pairFixtures.forEach(([crtShState, certspotterState, comparisonStatus], index) => {
    try {
      insertOverlap(db, {
        id: `ctpot-pair-${index}`,
        crtShState,
        certspotterState,
        comparisonStatus,
      });
    } catch (error) {
      pairFailures.push(`${crtShState}|${certspotterState}: ${error?.message || error}`);
    }
  });
  ok("coherence: every supported provider-state pair has an explicit accepted status",
    pairFailures.length === 0, pairFailures.join("; "));

  for (const [suffix, siblingState, siblingStatus] of [
    ["in-flight", "in_flight_at_consumer_release", "censored_in_flight"],
    ["not-started-wrong-precedence", "not_started", "not_started"],
  ]) {
    let rejected = false;
    try {
      insertOverlap(db, {
        id: `ctpot-platform-${suffix}`,
        crtShState: "terminal_platform_deadline_abort",
        certspotterState: siblingState,
        comparisonStatus: siblingStatus,
      });
    } catch { rejected = true; }
    ok(`coherence: platform plus ${suffix} rejects the non-platform status`, rejected);
  }
}

db.close();
console.log(`CT platform-abort migration: ${passed}/${passed + failed} assertions passed`);
if (failed > 0) process.exitCode = 1;
