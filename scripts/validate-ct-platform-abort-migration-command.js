#!/usr/bin/env node
// Prove migration 105's all-or-nothing behaviour with the governed production
// invocation form (`wrangler d1 execute --file`). The disposable test adds only
// `--local --persist-to`; migration parsing/transaction ownership remains D1's.
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { DatabaseSync } from "node:sqlite";
import { fileURLToPath } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const workerDir = path.join(root, "workers/scan-api");
const configPath = path.join(workerDir, "wrangler.toml");
const migration103 = fs.readFileSync(
  path.join(root, "database/migrations/103-ct-provider-telemetry.sql"), "utf8",
);
const migration104 = fs.readFileSync(
  path.join(root, "database/migrations/104-ct-provider-overlap-telemetry.sql"), "utf8",
);
const migration105 = fs.readFileSync(
  path.join(root, "database/migrations/105-ct-platform-deadline-provenance.sql"), "utf8",
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
const sha256 = (value) => crypto.createHash("sha256").update(value).digest("hex");

function replaceExactlyOnce(source, from, to, label) {
  const count = source.split(from).length - 1;
  if (count !== 1) throw new Error(`${label}: anchor count ${count}, expected 1`);
  return source.replace(from, to);
}

function setupSql() {
  const scans = Array.from({ length: 16 }, (_, index) =>
    `('scan-historical-${index}')`).join(",\n  ");
  const rows = Array.from({ length: 124 }, (_, index) => {
    const outcomes = [
      "ok", "timeout", "http_error", "parse_error", "rate_limited", "network_error",
    ];
    const outcome = outcomes[index % outcomes.length];
    const impact = index % 5 === 0 ? 1 : 0;
    const module = index % 2 === 0 ? "ssl" : "subdomains";
    const provider = index % 3 === 0 ? "certspotter" : "crt_sh";
    const status = outcome === "rate_limited" ? "429"
      : (outcome === "http_error" ? "503" : "NULL");
    const result = outcome === "ok" ? String(index % 17) : "NULL";
    const affected = impact
      ? `'${index % 2 === 0 ? "certificate_transparency" : "subdomain_discovery"}'`
      : "NULL";
    const cacheState = ["miss", "fresh_hit", "stale_available"][index % 3];
    const cacheAge = index % 4 === 0 ? "NULL" : String(index);
    const day = String(1 + (index % 28)).padStart(2, "0");
    const hour = String(index % 24).padStart(2, "0");
    const minute = String(index % 60).padStart(2, "0");
    return `(
      'ctpt-historical-${String(index).padStart(3, "0")}',
      'scan-historical-${Math.floor(index / 8)}', '${module}', '${provider}',
      '${outcome}', ${status}, ${100 + index}, ${result},
      '2026-07-${day}T${hour}:${minute}:00.000Z',
      '2026-07-${day}T${hour}:${minute}:01.000Z',
      ${impact}, ${affected}, '${cacheState}', ${cacheAge},
      '2026-08-01T${hour}:${minute}:02.000Z'
    )`;
  }).join(",\n  ");
  return `
PRAGMA foreign_keys = on;
CREATE TABLE scans (id TEXT PRIMARY KEY);
INSERT INTO scans (id) VALUES
  ${scans};
${migration103}
${migration104}
INSERT INTO ct_provider_overlap_telemetry (
  id, scan_id, module, source_set_version, observed_at,
  normalization_candidate_limit, retained_hostname_limit,
  crt_sh_attempt_state, certspotter_attempt_state, comparison_status,
  created_at
) VALUES (
  'ctpot-historical-000', 'scan-historical-0', 'subdomains',
  'ct-provider-overlap/1', '2026-08-01T00:00:00.000Z', 4096, 256,
  'terminal_failure', 'terminal_failure', 'censored_provider_failure',
  '2026-08-01T00:00:01.000Z'
);
INSERT INTO ct_provider_telemetry
  (id, scan_id, module, provider, outcome, http_status, latency_ms,
   result_count, started_at, completed_at, completeness_impact,
   affected_signal, cache_state, cache_age_s, created_at)
VALUES
  ${rows};
`;
}

function findSqlite(directory) {
  const found = [];
  const visit = (current) => {
    for (const entry of fs.readdirSync(current, { withFileTypes: true })) {
      const candidate = path.join(current, entry.name);
      if (entry.isDirectory()) visit(candidate);
      else if (entry.isFile()
        && candidate.endsWith(".sqlite")
        && path.basename(candidate) !== "metadata.sqlite") found.push(candidate);
    }
  };
  visit(directory);
  if (found.length !== 1) {
    throw new Error(`expected one local D1 sqlite file, found ${found.length}: ${found.join(", ")}`);
  }
  return found[0];
}

function executeFile(file, persistTo) {
  return spawnSync(
    "npx",
    [
      "wrangler", "d1", "execute", "cybermeters-db", "--local",
      "--persist-to", persistTo, "--file", file, "--config", configPath,
    ],
    { cwd: workerDir, encoding: "utf8", timeout: 60_000 },
  );
}

function snapshotDatabase(sqlitePath) {
  const db = new DatabaseSync(sqlitePath);
  const columns = db.prepare("PRAGMA table_info(ct_provider_telemetry)").all()
    .map((column) => column.name);
  const rows = db.prepare(
    `SELECT ${columns.map((column) => `"${column}"`).join(", ")}
     FROM ct_provider_telemetry ORDER BY id`,
  ).all();
  const overlapColumns = db.prepare("PRAGMA table_info(ct_provider_overlap_telemetry)").all()
    .map((column) => column.name);
  const overlapRows = db.prepare(
    `SELECT ${overlapColumns.map((column) => `"${column}"`).join(", ")}
     FROM ct_provider_overlap_telemetry ORDER BY id`,
  ).all();
  const tableSql = Object.fromEntries(db.prepare(
    `SELECT name, sql FROM sqlite_master
     WHERE type = 'table' AND name IN
       ('ct_provider_telemetry', 'ct_provider_overlap_telemetry')
     ORDER BY name`,
  ).all().map((row) => [row.name, row.sql]));
  const objectNames = db.prepare(
    `SELECT type, name FROM sqlite_master
     WHERE name IN (
       'ct_provider_telemetry', 'ct_provider_overlap_telemetry',
       'ct_provider_telemetry__105', 'ct_provider_overlap_telemetry__105',
       'ct_platform_deadline_migration_105_guard',
       'idx_ct_provider_telemetry_scan',
       'idx_ct_provider_telemetry_provider_time',
       'trg_ct_provider_telemetry_scan_row_bound',
       'idx_ct_provider_overlap_telemetry_scan',
       'idx_ct_provider_overlap_telemetry_status_time'
     ) ORDER BY type, name`,
  ).all();
  const metadata = {
    count: Number(db.prepare("SELECT COUNT(*) AS n FROM ct_provider_telemetry").get().n),
    fingerprint: sha256(JSON.stringify(rows)),
    overlapCount: Number(db.prepare(
      "SELECT COUNT(*) AS n FROM ct_provider_overlap_telemetry",
    ).get().n),
    overlapFingerprint: sha256(JSON.stringify(overlapRows)),
    objectNames,
    ctPk: db.prepare("PRAGMA table_info(ct_provider_telemetry)").all()
      .filter((row) => Number(row.pk) > 0).map((row) => [row.name, Number(row.pk)]),
    overlapPk: db.prepare("PRAGMA table_info(ct_provider_overlap_telemetry)").all()
      .filter((row) => Number(row.pk) > 0).map((row) => [row.name, Number(row.pk)]),
    overlapUnique: db.prepare("PRAGMA index_list(ct_provider_overlap_telemetry)").all()
      .filter((row) => row.origin === "u")
      .map((row) => db.prepare(`PRAGMA index_info(${row.name})`).all().map((column) => column.name)),
    foreignKeys: {
      ct: db.prepare("PRAGMA foreign_key_list(ct_provider_telemetry)").all(),
      overlap: db.prepare("PRAGMA foreign_key_list(ct_provider_overlap_telemetry)").all(),
    },
    foreignKeyViolations: db.prepare("PRAGMA foreign_key_check").all(),
    oldVocabularyOnly: !/platform_deadline_abort/i.test(
      `${tableSql.ct_provider_telemetry}\n${tableSql.ct_provider_overlap_telemetry}`,
    ),
  };
  db.close();
  return metadata;
}

const injections = [
  {
    name: "new overlap table creation",
    marker: "-- FAILURE_INJECTION_AFTER_NEW_TABLE_CREATION",
  },
  {
    name: "historical overlap row copy",
    marker: "-- FAILURE_INJECTION_AFTER_HISTORICAL_ROW_COPY",
  },
  {
    name: "old-table drop and rename boundary",
    marker: "-- FAILURE_INJECTION_AT_OLD_TABLE_DROP_RENAME_BOUNDARY",
  },
  {
    name: "first named-index recreation",
    marker: "-- FAILURE_INJECTION_AFTER_FIRST_NAMED_INDEX_RECREATION",
  },
  {
    name: "CT-R1 trigger recreation",
    marker: "-- FAILURE_INJECTION_DURING_TRIGGER_RECREATION",
  },
  {
    name: "first-table completion before second-table completion",
    marker: "-- FAILURE_INJECTION_AFTER_FIRST_TABLE_BEFORE_SECOND",
  },
];

ok("command: intended production form is governed wrangler d1 execute --file",
  migration105.includes(
    "-- npx wrangler d1 execute cybermeters-db --remote \\\n"
      + "--   --file=../../database/migrations/105-ct-platform-deadline-provenance.sql",
  ));

for (const injection of injections) {
  const temp = fs.mkdtempSync(path.join(os.tmpdir(), "cm-ct105-atomic-"));
  const persistTo = path.join(temp, "persist");
  fs.mkdirSync(persistTo);
  const setupPath = path.join(temp, "setup.sql");
  const mutantPath = path.join(temp, "migration-105-failure.sql");
  try {
    fs.writeFileSync(setupPath, setupSql());
    const setup = executeFile(setupPath, persistTo);
    if (setup.error || setup.signal || setup.status !== 0) {
      ok(`exact command rollback after ${injection.name}`, false,
        `setup status=${setup.status} signal=${setup.signal} ${setup.stderr || setup.stdout}`);
      continue;
    }
    const sqlitePath = findSqlite(persistTo);
    const before = snapshotDatabase(sqlitePath);
    fs.writeFileSync(mutantPath, replaceExactlyOnce(
      migration105,
      injection.marker,
      `${injection.marker}\nSELECT no_such_ct_migration_function();`,
      injection.name,
    ));
    const attempted = executeFile(mutantPath, persistTo);
    const after = snapshotDatabase(sqlitePath);
    const failedNormally = attempted.error == null && attempted.signal == null && attempted.status !== 0;
    ok(
      `exact command rollback after ${injection.name}`,
      failedNormally
        && before.count === 124
        && before.overlapCount === 1
        && JSON.stringify(after) === JSON.stringify(before)
        && after.oldVocabularyOnly
        && after.foreignKeyViolations.length === 0,
      `status=${attempted.status} signal=${attempted.signal} error=${attempted.error?.message || "none"}`
        + `\nbefore=${JSON.stringify(before)}\nafter=${JSON.stringify(after)}`
        + `\nstdout=${attempted.stdout || ""}\nstderr=${attempted.stderr || ""}`,
    );
  } finally {
    // Only the exact mkdtemp directory created above is removed. Refuse links or
    // any path outside the OS temp root before recursive cleanup.
    const resolved = fs.realpathSync(temp);
    const tempRoot = fs.realpathSync(os.tmpdir());
    if (resolved.startsWith(`${tempRoot}${path.sep}cm-ct105-atomic-`)
      && !fs.lstatSync(temp).isSymbolicLink()) {
      fs.rmSync(temp, { recursive: true, force: false });
    }
  }
}

console.log(`CT platform-abort exact-command atomicity: ${passed}/${passed + failed} assertions passed`);
if (failed > 0) process.exitCode = 1;
