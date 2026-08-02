#!/usr/bin/env node
// Mechanically derive CT-R2 PR-2A.1 migration 105 from applied migrations
// 103/104. Those history files are immutable inputs; this script refuses any
// source hash, vocabulary, table-shape, or insertion-site drift.
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const source103Path = path.join(root, "database/migrations/103-ct-provider-telemetry.sql");
const source104Path = path.join(root, "database/migrations/104-ct-provider-overlap-telemetry.sql");
const outputPath = path.join(root, "database/migrations/105-ct-platform-deadline-provenance.sql");

const EXPECTED_SOURCE_SHA256 = Object.freeze({
  [source103Path]: "487ad29fe0600ec9b353283c7e657b2e8fefab0bd8bc921f47c1616e8b371efa",
  [source104Path]: "b74e5961cf888d9f792b0de47b267971f68a1141607b4dbd92a4a43d20a8ce32",
});

const CT_COLUMNS = Object.freeze([
  "id", "scan_id", "module", "provider", "outcome", "http_status",
  "latency_ms", "result_count", "started_at", "completed_at",
  "completeness_impact", "affected_signal", "cache_state", "cache_age_s",
  "created_at",
]);
const OVERLAP_COLUMNS = Object.freeze([
  "id", "scan_id", "module", "source_set_version", "observed_at",
  "normalization_candidate_limit", "retained_hostname_limit",
  "crt_sh_attempt_state", "crt_sh_raw_record_count",
  "crt_sh_expanded_candidate_count", "crt_sh_normalization_input_count",
  "crt_sh_normalization_dropped_candidate_count",
  "crt_sh_normalization_truncated", "crt_sh_normalized_candidate_count",
  "crt_sh_unique_hostname_count", "crt_sh_retained_hostname_count",
  "crt_sh_dropped_hostname_count", "crt_sh_truncated",
  "certspotter_attempt_state", "certspotter_raw_record_count",
  "certspotter_expanded_candidate_count",
  "certspotter_normalization_input_count",
  "certspotter_normalization_dropped_candidate_count",
  "certspotter_normalization_truncated",
  "certspotter_normalized_candidate_count",
  "certspotter_unique_hostname_count",
  "certspotter_retained_hostname_count",
  "certspotter_dropped_hostname_count", "certspotter_truncated",
  "comparison_status", "intersection_count", "crt_sh_only_count",
  "certspotter_only_count", "union_count", "created_at",
]);

const sha256 = (value) => crypto.createHash("sha256").update(value).digest("hex");
const fail = (message) => { throw new Error(`migration 105 generation refused: ${message}`); };

function occurrenceCount(source, needle) {
  return source.split(needle).length - 1;
}

function assertOccurrences(source, needle, expected, label) {
  const actual = occurrenceCount(source, needle);
  if (actual !== expected) fail(`${label} occurrences=${actual}, expected=${expected}`);
}

function replaceOccurrences(source, needle, replacement, expected, label) {
  assertOccurrences(source, needle, expected, label);
  return source.split(needle).join(replacement);
}

function matchingParen(source, openIndex) {
  let depth = 0;
  let quote = null;
  for (let index = openIndex; index < source.length; index += 1) {
    const char = source[index];
    if (quote !== null) {
      if (char !== quote) continue;
      if (source[index + 1] === quote) { index += 1; continue; }
      quote = null;
      continue;
    }
    if (char === "'" || char === '"' || char === "`") { quote = char; continue; }
    if (char === "(") depth += 1;
    if (char === ")") {
      depth -= 1;
      if (depth === 0) return index;
    }
  }
  fail(`unterminated CREATE TABLE parenthesis at byte ${openIndex}`);
}

function tableParts(source, table) {
  const prefix = `CREATE TABLE IF NOT EXISTS ${table} (`;
  assertOccurrences(source, prefix, 1, `${table} CREATE TABLE`);
  const start = source.indexOf(prefix);
  const open = source.indexOf("(", start + prefix.length - 1);
  const close = matchingParen(source, open);
  if (source.slice(close, close + 2) !== ");") fail(`${table} CREATE TABLE lacks exact semicolon`);
  return {
    prefix,
    start,
    open,
    close,
    statement: source.slice(start, close + 2),
    body: source.slice(open + 1, close),
    suffix: source.slice(close + 2).trim(),
  };
}

function splitTopLevel(body) {
  const parts = [];
  let depth = 0;
  let quote = null;
  let start = 0;
  for (let index = 0; index < body.length; index += 1) {
    const char = body[index];
    if (quote !== null) {
      if (char !== quote) continue;
      if (body[index + 1] === quote) { index += 1; continue; }
      quote = null;
      continue;
    }
    if (char === "'" || char === '"' || char === "`") { quote = char; continue; }
    if (char === "(") depth += 1;
    else if (char === ")") depth -= 1;
    else if (char === "," && depth === 0) {
      parts.push(body.slice(start, index).trim());
      start = index + 1;
    }
  }
  parts.push(body.slice(start).trim());
  return parts;
}

function columnNames(body) {
  return splitTopLevel(body)
    .filter((definition) => !/^(?:CHECK|FOREIGN\s+KEY|UNIQUE|PRIMARY\s+KEY)\b/i.test(definition))
    .map((definition) => definition.match(/^([A-Za-z_][A-Za-z0-9_]*)\b/)?.[1] || "<invalid>");
}

function assertExactColumns(body, expected, table) {
  const actual = columnNames(body);
  if (JSON.stringify(actual) !== JSON.stringify(expected)) {
    fail(`${table} columns drifted: ${JSON.stringify(actual)}`);
  }
}

function formatColumnList(columns) {
  const lines = [];
  for (let index = 0; index < columns.length; index += 4) {
    const slice = columns.slice(index, index + 4).join(", ");
    lines.push(`    ${slice}${index + 4 < columns.length ? "," : ""}`);
  }
  return lines.join("\n");
}

function copyBlock(sourceTable, targetTable, columns) {
  const list = formatColumnList(columns);
  return `INSERT INTO ${targetTable} (\n${list}\n)\nSELECT\n${list}\nFROM ${sourceTable};`;
}

function generatedCreate(parts, sourceTable, targetTable, transform) {
  let statement = parts.statement.replace(
    `CREATE TABLE IF NOT EXISTS ${sourceTable} (`,
    `CREATE TABLE ${targetTable} (`,
  );
  statement = transform(statement);
  return statement;
}

function dependentObjects(parts, expectedIfNotExists, table) {
  assertOccurrences(parts.suffix, "IF NOT EXISTS ", expectedIfNotExists,
    `${table} dependent IF NOT EXISTS`);
  return parts.suffix.split("IF NOT EXISTS ").join("");
}

export function generateMigration105() {
  const source103 = fs.readFileSync(source103Path, "utf8");
  const source104 = fs.readFileSync(source104Path, "utf8");
  for (const [sourcePath, source] of [[source103Path, source103], [source104Path, source104]]) {
    const actual = sha256(source);
    if (actual !== EXPECTED_SOURCE_SHA256[sourcePath]) {
      fail(`${path.basename(sourcePath)} SHA-256 ${actual} != ${EXPECTED_SOURCE_SHA256[sourcePath]}`);
    }
  }

  const ct = tableParts(source103, "ct_provider_telemetry");
  const overlap = tableParts(source104, "ct_provider_overlap_telemetry");
  assertExactColumns(ct.body, CT_COLUMNS, "ct_provider_telemetry");
  assertExactColumns(overlap.body, OVERLAP_COLUMNS, "ct_provider_overlap_telemetry");

  const oldOutcome = "                              'rate_limited', 'network_error'";
  const newOutcome = "                              'rate_limited', 'network_error',\n"
    + "                              'platform_deadline_abort'";
  const oldAttemptStates = "                                              'terminal_success', 'terminal_failure',\n"
    + "                                              'not_started', 'in_flight_at_consumer_release'";
  const newAttemptStates = "                                              'terminal_success', 'terminal_failure',\n"
    + "                                              'terminal_platform_deadline_abort',\n"
    + "                                              'not_started', 'in_flight_at_consumer_release'";
  const oldComparisonStatuses = "                                              'compared', 'compared_truncated',\n"
    + "                                              'censored_provider_failure',\n"
    + "                                              'censored_in_flight', 'not_started'";
  const newComparisonStatuses = "                                              'compared', 'compared_truncated',\n"
    + "                                              'censored_provider_failure',\n"
    + "                                              'censored_platform_deadline_abort',\n"
    + "                                              'censored_in_flight', 'not_started'";
  const ctTail = "    created_at            TEXT NOT NULL DEFAULT (datetime('now')),\n"
    + "    FOREIGN KEY (scan_id) REFERENCES scans(id)\n";
  const ctTailWithCoherence = "    created_at            TEXT NOT NULL DEFAULT (datetime('now')),\n"
    + "    FOREIGN KEY (scan_id) REFERENCES scans(id),\n"
    + "    CHECK (\n"
    + "      outcome != 'platform_deadline_abort' OR\n"
    + "      (http_status IS NULL AND result_count IS NULL)\n"
    + "    )\n";
  const overlapTail = "    CHECK (\n"
    + "      comparison_status != 'not_started' OR\n"
    + "      (crt_sh_attempt_state = 'not_started' OR certspotter_attempt_state = 'not_started')\n"
    + "    )\n";
  const overlapTailWithCoherence = "    CHECK (\n"
    + "      comparison_status != 'not_started' OR\n"
    + "      (crt_sh_attempt_state = 'not_started' OR certspotter_attempt_state = 'not_started')\n"
    + "    ),\n"
    + "    CHECK (\n"
    + "      (\n"
    + "        comparison_status = 'censored_platform_deadline_abort' AND\n"
    + "        (crt_sh_attempt_state = 'terminal_platform_deadline_abort' OR\n"
    + "         certspotter_attempt_state = 'terminal_platform_deadline_abort') AND\n"
    + "        crt_sh_attempt_state != 'in_flight_at_consumer_release' AND\n"
    + "        certspotter_attempt_state != 'in_flight_at_consumer_release'\n"
    + "      ) OR (\n"
    + "        comparison_status != 'censored_platform_deadline_abort' AND\n"
    + "        crt_sh_attempt_state != 'terminal_platform_deadline_abort' AND\n"
    + "        certspotter_attempt_state != 'terminal_platform_deadline_abort'\n"
    + "      )\n"
    + "    )\n";

  const ctCreate = generatedCreate(
    ct,
    "ct_provider_telemetry",
    "ct_provider_telemetry__105",
    (statement) => {
      let transformed = replaceOccurrences(statement, oldOutcome, newOutcome, 1,
        "CT-R1 outcome vocabulary");
      transformed = replaceOccurrences(transformed, ctTail, ctTailWithCoherence, 1,
        "CT-R1 platform outcome coherence insertion");
      return transformed;
    },
  );
  const overlapCreate = generatedCreate(
    overlap,
    "ct_provider_overlap_telemetry",
    "ct_provider_overlap_telemetry__105",
    (statement) => {
      let transformed = replaceOccurrences(statement, oldAttemptStates, newAttemptStates, 2,
        "overlap attempt-state vocabulary");
      transformed = replaceOccurrences(transformed, oldComparisonStatuses,
        newComparisonStatuses, 1, "overlap comparison-status vocabulary");
      transformed = replaceOccurrences(transformed, overlapTail,
        overlapTailWithCoherence, 1, "overlap reverse/coherence CHECK insertion");
      return transformed;
    },
  );

  let overlapObjects = dependentObjects(overlap, 2, "ct_provider_overlap_telemetry");
  const firstOverlapIndex = "CREATE INDEX idx_ct_provider_overlap_telemetry_scan\n"
    + "  ON ct_provider_overlap_telemetry (scan_id, observed_at);";
  overlapObjects = replaceOccurrences(
    overlapObjects,
    firstOverlapIndex,
    `${firstOverlapIndex}\n-- FAILURE_INJECTION_AFTER_FIRST_NAMED_INDEX_RECREATION`,
    1,
    "first overlap named-index marker",
  );
  let ctObjects = dependentObjects(ct, 3, "ct_provider_telemetry");
  ctObjects = replaceOccurrences(
    ctObjects,
    "END;",
    "END;\n-- FAILURE_INJECTION_DURING_TRIGGER_RECREATION",
    1,
    "CT-R1 trigger marker",
  );

  const overlapCopy = copyBlock(
    "ct_provider_overlap_telemetry", "ct_provider_overlap_telemetry__105", OVERLAP_COLUMNS,
  );
  const ctCopy = copyBlock(
    "ct_provider_telemetry", "ct_provider_telemetry__105", CT_COLUMNS,
  );

  return `-- GENERATED by scripts/generate-migration-105.js from applied migrations 103/104.\n`
    + `-- Do not edit this file directly; regenerate and run the migration-105 proofs.\n`
    + `-- Founder gate: prepared only. Never apply to production as part of this PR.\n\n`
    + `-- Governed production carrier after a separate founder gate:\n`
    + `-- npx wrangler d1 execute cybermeters-db --remote \\\n`
    + `--   --file=../../database/migrations/105-ct-platform-deadline-provenance.sql\n\n`
    + `PRAGMA defer_foreign_keys = on;\n\n`
    + `CREATE TABLE ct_platform_deadline_migration_105_guard (\n`
    + `    table_name    TEXT PRIMARY KEY,\n`
    + `    source_count INTEGER NOT NULL,\n`
    + `    copied_count INTEGER NOT NULL,\n`
    + `    CHECK (source_count = copied_count)\n`
    + `);\n\n`
    + `${overlapCreate}\n`
    + `-- FAILURE_INJECTION_AFTER_NEW_TABLE_CREATION\n\n`
    + `${overlapCopy}\n`
    + `-- FAILURE_INJECTION_AFTER_HISTORICAL_ROW_COPY\n\n`
    + `INSERT INTO ct_platform_deadline_migration_105_guard\n`
    + `    (table_name, source_count, copied_count)\n`
    + `SELECT 'ct_provider_overlap_telemetry',\n`
    + `       (SELECT COUNT(*) FROM ct_provider_overlap_telemetry),\n`
    + `       (SELECT COUNT(*) FROM ct_provider_overlap_telemetry__105);\n\n`
    + `DROP TABLE ct_provider_overlap_telemetry;\n`
    + `ALTER TABLE ct_provider_overlap_telemetry__105\n`
    + `  RENAME TO ct_provider_overlap_telemetry;\n`
    + `-- FAILURE_INJECTION_AT_OLD_TABLE_DROP_RENAME_BOUNDARY\n\n`
    + `${overlapObjects}\n`
    + `-- FAILURE_INJECTION_AFTER_FIRST_TABLE_BEFORE_SECOND\n\n`
    + `${ctCreate}\n\n`
    + `${ctCopy}\n\n`
    + `INSERT INTO ct_platform_deadline_migration_105_guard\n`
    + `    (table_name, source_count, copied_count)\n`
    + `SELECT 'ct_provider_telemetry',\n`
    + `       (SELECT COUNT(*) FROM ct_provider_telemetry),\n`
    + `       (SELECT COUNT(*) FROM ct_provider_telemetry__105);\n\n`
    + `DROP TABLE ct_provider_telemetry;\n`
    + `ALTER TABLE ct_provider_telemetry__105 RENAME TO ct_provider_telemetry;\n\n`
    + `${ctObjects}\n\n`
    + `INSERT INTO ct_platform_deadline_migration_105_guard\n`
    + `    (table_name, source_count, copied_count)\n`
    + `SELECT 'ct_provider_telemetry_scan_fk', 0, COUNT(*)\n`
    + `FROM ct_provider_telemetry AS telemetry\n`
    + `LEFT JOIN scans ON scans.id = telemetry.scan_id\n`
    + `WHERE scans.id IS NULL;\n\n`
    + `INSERT INTO ct_platform_deadline_migration_105_guard\n`
    + `    (table_name, source_count, copied_count)\n`
    + `SELECT 'ct_provider_overlap_telemetry_scan_fk', 0, COUNT(*)\n`
    + `FROM ct_provider_overlap_telemetry AS telemetry\n`
    + `LEFT JOIN scans ON scans.id = telemetry.scan_id\n`
    + `WHERE scans.id IS NULL;\n\n`
    + `DROP TABLE ct_platform_deadline_migration_105_guard;\n\n`
    + `PRAGMA foreign_key_check;\n`;
}

function main() {
  const generated = generateMigration105();
  if (process.argv.includes("--stdout")) {
    process.stdout.write(generated);
    return;
  }
  if (process.argv.includes("--check")) {
    const existing = fs.existsSync(outputPath) ? fs.readFileSync(outputPath, "utf8") : null;
    if (existing !== generated) fail(`${path.relative(root, outputPath)} is not generator-exact`);
  } else {
    fs.writeFileSync(outputPath, generated);
  }
  console.log(`${path.relative(root, outputPath)} ${Buffer.byteLength(generated)} bytes sha256=${sha256(generated)}`);
}

const isMain = process.argv[1]
  && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isMain) {
  try { main(); }
  catch (error) {
    console.error(error?.message || error);
    process.exit(1);
  }
}
