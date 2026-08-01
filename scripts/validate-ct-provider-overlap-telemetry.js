#!/usr/bin/env node
// CT-R2 PR-2A focused fixtures: real subdomains production function, bounded
// overlap collector, append-only persistence, tenancy, purge and raw-data safety.
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const migrationPath = process.env.CT_OVERLAP_MIGRATION_PATH || path.join(
  root,
  "database/migrations/104-ct-provider-overlap-telemetry.sql",
);
const indexSourcePath = process.env.CT_OVERLAP_INDEX_SOURCE_PATH || path.join(
  root,
  "workers/scan-api/src/index.js",
);
const tenantResourcesPath = process.env.CT_OVERLAP_TENANT_RESOURCES_PATH || path.join(
  root,
  "scripts/security/lib/tenant-resources.js",
);
const engineUrl = (name) => pathToFileURL(path.join(
  root,
  "workers/scan-api/src/engines",
  name,
)).href;
const overlapModuleUrl = process.env.CT_OVERLAP_MODULE_URL
  || engineUrl("ct-provider-overlap.js");
const overlapModule = await import(overlapModuleUrl);
const subdomainsModule = await import(
  process.env.CT_OVERLAP_SUBDOMAINS_MODULE_URL || engineUrl("subdomains-scan.js")
);
const {
  createCtProviderOverlapCollector,
  persistCtProviderOverlapTelemetry,
  CT_PROVIDER_OVERLAP_ATTEMPT_STATES,
  CT_PROVIDER_OVERLAP_COMPARISON_STATUSES,
  CT_PROVIDER_OVERLAP_NORMALIZATION_LIMIT,
  CT_PROVIDER_OVERLAP_RETAINED_LIMIT,
  CT_PROVIDER_OVERLAP_SOURCE_SET_VERSION,
} = overlapModule;
const { runSubdomainsModule } = subdomainsModule;

const NOW = "2026-08-02T10:00:00.000Z";
const NOW_MS = Date.parse(NOW);
let passed = 0;
let failed = 0;
const ok = (name, condition, detail = "") => {
  if (condition) passed += 1;
  else {
    failed += 1;
    console.error(`FAIL ${name}${detail ? ` — ${detail}` : ""}`);
  }
};
const eq = (name, got, want) =>
  ok(name, got === want, `got ${JSON.stringify(got)} want ${JSON.stringify(want)}`);
const sha256 = (value) => crypto.createHash("sha256").update(value).digest("hex");

const available = (provider, data) => ({
  provider,
  domain: "example.com",
  status: "available",
  data,
  error: null,
});
const unavailable = (provider) => ({
  provider,
  domain: "example.com",
  status: "unavailable",
  data: null,
  error: `${provider} fixture unavailable`,
});

function makeCtCache({ crt_sh, certspotter }) {
  return {
    get: async (_domain, provider) => provider === "crt_sh" ? crt_sh : certspotter,
  };
}

const CRT_PARTIAL = [
  { name_value: "a.example.com\nshared.example.com", common_name: "a.example.com" },
];
const CERT_PARTIAL = [
  { dns_names: ["shared.example.com", "b.example.com"] },
];

const FIXTURES = [
  {
    name: "partial overlap",
    crt_sh: available("crt_sh", CRT_PARTIAL),
    certspotter: available("certspotter", CERT_PARTIAL),
    expected: { status: "compared", intersection: 1, crtOnly: 1, certOnly: 1, union: 3 },
  },
  {
    name: "identical sets",
    crt_sh: available("crt_sh", [{ name_value: "a.example.com\nb.example.com", common_name: "" }]),
    certspotter: available("certspotter", [{ dns_names: ["b.example.com", "a.example.com"] }]),
    expected: { status: "compared", intersection: 2, crtOnly: 0, certOnly: 0, union: 2 },
  },
  {
    name: "disjoint sets",
    crt_sh: available("crt_sh", [{ name_value: "a.example.com", common_name: "" }]),
    certspotter: available("certspotter", [{ dns_names: ["b.example.com"] }]),
    expected: { status: "compared", intersection: 0, crtOnly: 1, certOnly: 1, union: 2 },
  },
  {
    name: "duplicate hostnames",
    crt_sh: available("crt_sh", [{ name_value: "a.example.com\na.example.com", common_name: "a.example.com" }]),
    certspotter: available("certspotter", [{ dns_names: ["a.example.com", "a.example.com"] }]),
    expected: { status: "compared", intersection: 1, crtOnly: 0, certOnly: 0, union: 1 },
    check: (row) => row.crt_sh_normalized_candidate_count === 3
      && row.crt_sh_unique_hostname_count === 1
      && row.certspotter_normalized_candidate_count === 2
      && row.certspotter_unique_hostname_count === 1,
  },
  {
    name: "crt multi-name record and common name",
    crt_sh: available("crt_sh", [{
      name_value: "a.example.com\nb.example.com\nshared.example.com",
      common_name: "cn.example.com",
    }]),
    certspotter: available("certspotter", [{ dns_names: ["shared.example.com"] }]),
    expected: { status: "compared", intersection: 1, crtOnly: 3, certOnly: 0, union: 4 },
    check: (row) => row.crt_sh_raw_record_count === 1
      && row.crt_sh_expanded_candidate_count === 4
      && row.crt_sh_normalized_candidate_count === 4,
  },
  {
    name: "invalid out-of-domain wildcard candidates",
    crt_sh: available("crt_sh", [{
      name_value: "valid.example.com\n*.example.com\noutside.test\nnot a host",
      common_name: "example.com",
    }]),
    certspotter: available("certspotter", [{ dns_names: ["valid.example.com", "*.example.com"] }]),
    expected: { status: "compared", intersection: 1, crtOnly: 1, certOnly: 0, union: 2 },
    check: (row) => row.crt_sh_expanded_candidate_count === 5
      && row.crt_sh_normalized_candidate_count === 2
      && row.certspotter_expanded_candidate_count === 2
      && row.certspotter_normalized_candidate_count === 1,
  },
  {
    name: "both successful empty",
    crt_sh: available("crt_sh", []),
    certspotter: available("certspotter", []),
    expected: { status: "compared", intersection: 0, crtOnly: 0, certOnly: 0, union: 0 },
    check: (row) => row.crt_sh_raw_record_count === 0
      && row.certspotter_raw_record_count === 0
      && row.crt_sh_unique_hostname_count === 0
      && row.certspotter_unique_hostname_count === 0,
  },
  {
    name: "crt failure certspotter success",
    crt_sh: unavailable("crt_sh"),
    certspotter: available("certspotter", CERT_PARTIAL),
    expected: { status: "censored_provider_failure" },
    states: ["terminal_failure", "terminal_success"],
  },
  {
    name: "certspotter failure crt success",
    crt_sh: available("crt_sh", CRT_PARTIAL),
    certspotter: unavailable("certspotter"),
    expected: { status: "censored_provider_failure" },
    states: ["terminal_success", "terminal_failure"],
  },
  {
    name: "both provider failure",
    crt_sh: unavailable("crt_sh"),
    certspotter: unavailable("certspotter"),
    expected: { status: "censored_provider_failure" },
    states: ["terminal_failure", "terminal_failure"],
  },
];

const originalFetch = globalThis.fetch;
const originalRandom = Math.random;
globalThis.fetch = async (input) => {
  const url = new URL(String(input));
  if (url.hostname === "cloudflare-dns.com" || url.hostname === "dns.google") {
    return new Response(JSON.stringify({ Status: 0, Answer: [] }), {
      status: 200,
      headers: { "content-type": "application/json" },
    });
  }
  throw new Error(`unexpected fixture fetch ${url.hostname}`);
};
Math.random = () => 0.123456789;

if (process.env.CT_OVERLAP_BASELINE_ONLY === "1") {
  const hashes = {};
  for (const fixture of FIXTURES) {
    const result = await runSubdomainsModule("example.com", {
      ctCache: makeCtCache(fixture),
    });
    hashes[fixture.name] = sha256(JSON.stringify(result));
  }
  globalThis.fetch = originalFetch;
  Math.random = originalRandom;
  console.log(`CT_OVERLAP_BASELINE ${JSON.stringify(hashes)}`);
  process.exit(0);
}

async function executeFixture(fixture, collectorOptions = {}) {
  const ctCache = makeCtCache(fixture);
  const disabled = await runSubdomainsModule("example.com", { ctCache });
  const collector = createCtProviderOverlapCollector({
    now: () => NOW_MS,
    ...collectorOptions,
  });
  const enabled = await runSubdomainsModule("example.com", {
    ctCache: makeCtCache(fixture),
    ctOverlap: collector,
  });
  return {
    disabled,
    enabled,
    disabledBytes: JSON.stringify(disabled),
    enabledBytes: JSON.stringify(enabled),
    row: collector.snapshot(),
  };
}

const baselineHashes = {};
let rawLeakProbe = null;
try {
  for (const fixture of FIXTURES) {
    const result = await executeFixture(fixture);
    baselineHashes[fixture.name] = sha256(result.disabledBytes);
    if (fixture.name === "partial overlap") rawLeakProbe = result.row;
    eq(`${fixture.name}: instrumentation on/off production JSON byte-identical`,
      result.enabledBytes, result.disabledBytes);
    eq(`${fixture.name}: comparison status`,
      result.row.comparison_status, fixture.expected.status);
    if (["compared", "compared_truncated"].includes(fixture.expected.status)) {
      eq(`${fixture.name}: intersection count`, result.row.intersection_count, fixture.expected.intersection);
      eq(`${fixture.name}: crt.sh-only count`, result.row.crt_sh_only_count, fixture.expected.crtOnly);
      eq(`${fixture.name}: CertSpotter-only count`, result.row.certspotter_only_count, fixture.expected.certOnly);
      eq(`${fixture.name}: union count`, result.row.union_count, fixture.expected.union);
    } else {
      eq(`${fixture.name}: censored overlap fields are NULL`,
        [
          result.row.intersection_count,
          result.row.crt_sh_only_count,
          result.row.certspotter_only_count,
          result.row.union_count,
        ].every((value) => value === null), true);
    }
    if (fixture.states) {
      eq(`${fixture.name}: provider attempt states`,
        `${result.row.crt_sh_attempt_state}|${result.row.certspotter_attempt_state}`,
        fixture.states.join("|"));
    }
    if (fixture.check) eq(`${fixture.name}: count dictionary`, fixture.check(result.row), true);
  }

  // The fixture hashes pin the customer-result bytes that the parity comparison
  // above exercises. Any PER_CAP/MERGE_CAP/provider-order change changes at least
  // one fingerprint instead of letting both sides drift together.
  const expectedBaselineHashes = {
    // Filled from exact base 7673bc2 with Math.random fixed above.
    "partial overlap": "4baa8d7134d78a2deb27a3304b9fa2da39cd965d02c41ea09d67004ede0c2b94",
    "identical sets": "a24b87d298f4e7521a44b49cec0910f162b679715d4e84ad00608c33b7b0f3e7",
    "disjoint sets": "0476e9c000dc615775fc1a2a6c59f2801bb66c3a5225955bab5220960c86bdb4",
    "duplicate hostnames": "a8d7548fd5dcc6e5c56ddfe54511488e63113f593a66e0e6417b6a790604f24b",
    "crt multi-name record and common name": "2eaaf3a9b0543ae803025bf98d45a4794120d8e96401c728722d525b5898c4ff",
    "invalid out-of-domain wildcard candidates": "a845c5e46880eab9a0b8e8d7609439c4553c9341b9061aecbb166c6d3b7e482f",
    "both successful empty": "c9094db96395e5170c665c9c4b7599db333f788961e71b766f687f789cb97ad9",
    "crt failure certspotter success": "fad76101fbcdc367c6e5781c9d39ade49f83057e3e34f9215711c2f3b35ef0db",
    "certspotter failure crt success": "639c1725c9f4ab97bbc0eaf8ebf54622db4735f27183a1f038f97031640a028a",
    "both provider failure": "afdf74816197466e4bdf5b9ddc638ec2f630e0d580c26d5907f8817b79580deb",
  };
  if (process.env.CT_OVERLAP_PRINT_BASELINE === "1") {
    console.error(`CT_OVERLAP_BASELINE ${JSON.stringify(baselineHashes)}`);
  }
  eq("exact-base production-result fixture fingerprint",
    JSON.stringify(baselineHashes), JSON.stringify(expectedBaselineHashes));
  eq("telemetry snapshot exposes counts only, never raw hostnames",
    JSON.stringify(rawLeakProbe).includes(".example.com"), false);

  // Explicit truncation: all normalization remains below its own cap while the
  // comparison retains only two of four unique names from each provider.
  const truncation = await executeFixture({
    crt_sh: available("crt_sh", [{
      name_value: "a.example.com\nb.example.com\nc.example.com\nd.example.com",
      common_name: "",
    }]),
    certspotter: available("certspotter", [{
      dns_names: ["a.example.com", "b.example.com", "e.example.com", "f.example.com"],
    }]),
  }, { retainedLimit: 2 });
  eq("truncation: production JSON byte-identical", truncation.enabledBytes, truncation.disabledBytes);
  eq("truncation: comparison status is censored", truncation.row.comparison_status, "compared_truncated");
  eq("truncation: crt.sh unique/retained/dropped counts",
    `${truncation.row.crt_sh_unique_hostname_count}/${truncation.row.crt_sh_retained_hostname_count}/${truncation.row.crt_sh_dropped_hostname_count}`,
    "4/2/2");
  eq("truncation: CertSpotter unique/retained/dropped counts",
    `${truncation.row.certspotter_unique_hostname_count}/${truncation.row.certspotter_retained_hostname_count}/${truncation.row.certspotter_dropped_hostname_count}`,
    "4/2/2");
  eq("truncation: boolean agrees with dropped counts",
    truncation.row.crt_sh_truncated && truncation.row.certspotter_truncated, true);
  eq("truncation: overlap belongs only to retained bounded sets",
    `${truncation.row.intersection_count}/${truncation.row.crt_sh_only_count}/${truncation.row.certspotter_only_count}/${truncation.row.union_count}`,
    "2/0/0/2");

  // Separate normalization censorship. The exact measured prefix remains
  // countable, and the unnormalised suffix is explicit rather than silently
  // presented as provider-wide coverage.
  const normalizationCensored = await executeFixture({
    crt_sh: available("crt_sh", [{ name_value: "a.example.com\nb.example.com\nc.example.com", common_name: "" }]),
    certspotter: available("certspotter", [{ dns_names: ["a.example.com", "b.example.com", "c.example.com"] }]),
  }, { normalizationLimit: 2, retainedLimit: 2 });
  eq("normalization bound: comparison is censored", normalizationCensored.row.comparison_status, "compared_truncated");
  eq("normalization bound: skipped candidate count is explicit",
    `${normalizationCensored.row.crt_sh_normalization_input_count}/${normalizationCensored.row.crt_sh_normalization_dropped_candidate_count}/${normalizationCensored.row.crt_sh_normalization_truncated}`,
    "2/1/true");
  eq("normalization bound: production JSON byte-identical",
    normalizationCensored.enabledBytes, normalizationCensored.disabledBytes);

  // Collector defects are observational and cannot change customer output.
  const exceptionFixture = FIXTURES[0];
  const expected = await runSubdomainsModule("example.com", {
    ctCache: makeCtCache(exceptionFixture),
  });
  const throwingCollector = {
    begin() { throw new Error("fixture collector begin failure"); },
    observe() { throw new Error("fixture collector observe failure"); },
  };
  const withThrowingCollector = await runSubdomainsModule("example.com", {
    ctCache: makeCtCache(exceptionFixture),
    ctOverlap: throwingCollector,
  });
  eq("collector exception: production result byte-identical",
    JSON.stringify(withThrowingCollector), JSON.stringify(expected));

  // A collector that was never passed to the module creates no synthetic row.
  const neverStarted = createCtProviderOverlapCollector({ now: () => NOW_MS });
  eq("module never ran: collector snapshot is empty", neverStarted.snapshot(), null);

  // Future-state reachability is schema-ready but not fabricated by normal PR-2A.
  const inFlight = createCtProviderOverlapCollector({ now: () => NOW_MS });
  inFlight.begin("crt_sh");
  inFlight.begin("certspotter");
  eq("in-flight consumer release is represented honestly",
    inFlight.snapshot().comparison_status, "censored_in_flight");
  const notStarted = createCtProviderOverlapCollector({ now: () => NOW_MS });
  notStarted.begin("crt_sh");
  notStarted.observe("crt_sh", { status: "fulfilled", value: available("crt_sh", []) }, "example.com");
  eq("one provider never started remains distinct",
    notStarted.snapshot().comparison_status, "not_started");

  eq("attempt-state vocabulary is future-ready",
    CT_PROVIDER_OVERLAP_ATTEMPT_STATES.join("|"),
    "terminal_success|terminal_failure|not_started|in_flight_at_consumer_release");
  eq("comparison-status vocabulary is frozen",
    CT_PROVIDER_OVERLAP_COMPARISON_STATUSES.join("|"),
    "compared|compared_truncated|censored_provider_failure|censored_in_flight|not_started");
  eq("source-set version is explicit",
    CT_PROVIDER_OVERLAP_SOURCE_SET_VERSION, "ct-provider-overlap/1");
  eq("normalization bound is separate from production caps",
    CT_PROVIDER_OVERLAP_NORMALIZATION_LIMIT, 4_096);
  eq("comparison retention bound is separate from production caps",
    CT_PROVIDER_OVERLAP_RETAINED_LIMIT, 256);
} finally {
  globalThis.fetch = originalFetch;
  Math.random = originalRandom;
}

function buildDb() {
  const db = new DatabaseSync(":memory:");
  db.exec("PRAGMA foreign_keys = ON");
  db.exec("CREATE TABLE scans (id TEXT PRIMARY KEY, workspace_id TEXT NOT NULL)");
  db.exec(fs.readFileSync(migrationPath, "utf8"));
  db.exec("INSERT INTO scans (id, workspace_id) VALUES ('scan-a', 'ws-a'), ('scan-b', 'ws-b')");
  return db;
}

function makeD1(db, { fail = false } = {}) {
  const calls = [];
  const statement = (sql, args = []) => ({
    sql,
    args,
    bind: (...bound) => statement(sql, bound),
    run: async () => {
      calls.push({ sql, args });
      if (fail && /ct_provider_overlap_telemetry/i.test(sql)) {
        throw new Error("fixture D1 database unavailable");
      }
      const result = db.prepare(sql).run(...args);
      return { success: true, meta: { changes: result.changes } };
    },
    all: async () => {
      calls.push({ sql, args });
      if (fail && /ct_provider_overlap_telemetry/i.test(sql)) {
        throw new Error("fixture D1 database unavailable");
      }
      return { success: true, results: db.prepare(sql).all(...args) };
    },
  });
  return {
    calls,
    binding: {
      prepare: (sql) => statement(sql),
      batch: async (statements) => {
        db.exec("BEGIN");
        try {
          const results = [];
          for (const entry of statements) {
            results.push(/^\s*select/i.test(entry.sql) ? await entry.all() : await entry.run());
          }
          db.exec("COMMIT");
          return results;
        } catch (error) {
          db.exec("ROLLBACK");
          throw error;
        }
      },
    },
  };
}

const persistenceMeasurementCollector = createCtProviderOverlapCollector({ now: () => NOW_MS });
persistenceMeasurementCollector.begin("crt_sh");
persistenceMeasurementCollector.begin("certspotter");
persistenceMeasurementCollector.observe("crt_sh", {
  status: "fulfilled", value: available("crt_sh", CRT_PARTIAL),
}, "example.com");
persistenceMeasurementCollector.observe("certspotter", {
  status: "fulfilled", value: available("certspotter", CERT_PARTIAL),
}, "example.com");
const persistenceMeasurement = persistenceMeasurementCollector.snapshot();

{
  const db = buildDb();
  const d1 = makeD1(db);
  const env = { cybermeters_db: d1.binding };
  const first = await persistCtProviderOverlapTelemetry("scan-a", persistenceMeasurement, env);
  eq("persistence: first write returns persisted(count)",
    `${first.status}(${first.count})`, "persisted(1)");
  const second = await persistCtProviderOverlapTelemetry("scan-a", persistenceMeasurement, env);
  eq("persistence: repeated write returns one durable row",
    `${second.status}(${second.count})`, "persisted(1)");
  eq("persistence: unique gate keeps one row",
    db.prepare("SELECT COUNT(*) AS n FROM ct_provider_overlap_telemetry WHERE scan_id='scan-a'").get().n,
    1);
  eq("persistence: module-not-run returns explicit empty outcome",
    (await persistCtProviderOverlapTelemetry("scan-a", null, env)).status,
    "not_attempted_empty");
  eq("persistence: no raw hostname is bound or persisted",
    d1.calls.some((call) => JSON.stringify(call.args).includes("a.example.com")), false);
  eq("persistence: telemetry row carries no workspace_id copy",
    db.prepare("PRAGMA table_info(ct_provider_overlap_telemetry)").all()
      .some((column) => column.name === "workspace_id"), false);
  eq("tenant attribution: canonical scan join finds owning workspace",
    db.prepare(`SELECT COUNT(*) AS n
      FROM ct_provider_overlap_telemetry t JOIN scans s ON s.id=t.scan_id
      WHERE t.scan_id='scan-a' AND s.workspace_id='ws-a'`).get().n, 1);
  const foreign = db.prepare(`SELECT COUNT(*) AS n
    FROM ct_provider_overlap_telemetry t JOIN scans s ON s.id=t.scan_id
    WHERE t.scan_id='scan-a' AND s.workspace_id=?`).get("ws-b").n;
  const nonexistent = db.prepare(`SELECT COUNT(*) AS n
    FROM ct_provider_overlap_telemetry t JOIN scans s ON s.id=t.scan_id
    WHERE t.scan_id='scan-a' AND s.workspace_id=?`).get("ws-missing").n;
  eq("tenant attribution: foreign and nonexistent workspace are indistinguishable",
    `${foreign}/${nonexistent}`, "0/0");
}

{
  const db = buildDb();
  const d1 = makeD1(db, { fail: true });
  const terminalResult = JSON.stringify({ status: "completed", report_ready: true });
  const outcome = await persistCtProviderOverlapTelemetry(
    "scan-a",
    persistenceMeasurement,
    { cybermeters_db: d1.binding },
  );
  eq("persistence failure: structured status", outcome.status, "persistence_failed");
  eq("persistence failure: safe error class", outcome.error_class, "db_unavailable");
  eq("persistence failure: durability is honestly unknown", outcome.durability, "unknown");
  eq("persistence failure: terminal result remains byte-identical",
    JSON.stringify({ status: "completed", report_ready: true }), terminalResult);
}

{
  const db = buildDb();
  const d1 = makeD1(db);
  const outcome = await persistCtProviderOverlapTelemetry(
    "scan-missing",
    persistenceMeasurement,
    { cybermeters_db: d1.binding },
  );
  eq("nonexistent scan FK: persistence fails safely", outcome.status, "persistence_failed");
  eq("nonexistent scan FK: no orphan row", db.prepare(
    "SELECT COUNT(*) AS n FROM ct_provider_overlap_telemetry",
  ).get().n, 0);
}

// Schema and governance are load-bearing, not documentation-only assertions.
{
  const migration = fs.readFileSync(migrationPath, "utf8");
  const executable = migration
    .replace(/--[^\n]*/g, "")
    .replace(/\/\*[\s\S]*?\*\//g, "");
  ok("migration 104 is additive", /CREATE TABLE IF NOT EXISTS ct_provider_overlap_telemetry/i.test(migration)
    && !/\b(DROP\s+TABLE|DROP\s+COLUMN|DELETE\s+FROM|TRUNCATE)\b/i.test(executable));
  ok("migration 104 has scan FK", /FOREIGN KEY \(scan_id\) REFERENCES scans\(id\)/i.test(migration));
  ok("migration 104 has source-version idempotency gate",
    /UNIQUE \(scan_id, module, source_set_version\)/i.test(migration));
  ok("migration 104 constrains module to subdomains", /CHECK \(module = 'subdomains'\)/i.test(migration));
  for (const state of CT_PROVIDER_OVERLAP_ATTEMPT_STATES) {
    ok(`migration 104 freezes attempt state ${state}`, migration.includes(`'${state}'`));
  }
  for (const status of CT_PROVIDER_OVERLAP_COMPARISON_STATUSES) {
    ok(`migration 104 freezes comparison status ${status}`, migration.includes(`'${status}'`));
  }
  ok("migration 104 has no raw-hostname column",
    !/\b(hostname|raw_hostname|hostname_sample|provider_payload)\b/i.test(executable));

  const indexSource = fs.readFileSync(indexSourcePath, "utf8");
  ok("purge order includes overlap telemetry as a scan child",
    /SCAN_CHILD_TABLES[\s\S]*ct_provider_overlap_telemetry/.test(indexSource));
  const resources = fs.readFileSync(tenantResourcesPath, "utf8");
  ok("tenant resource inventory includes overlap telemetry via scans",
    /class: "scans"[\s\S]*ct_provider_overlap_telemetry/.test(resources));
  const matrix = JSON.parse(fs.readFileSync(path.join(
    root,
    "scripts/security/tenant-isolation-matrix.json",
  ), "utf8"));
  eq("isolation matrix owns overlap telemetry through scan",
    matrix.table_index.ct_provider_overlap_telemetry, "scans");
  const helperSource = fs.readFileSync(fileURLToPath(overlapModuleUrl), "utf8");
  ok("overlap helper has no logging sink", !/\bconsole\s*\./.test(helperSource));
  ok("overlap persistence never updates telemetry rows",
    !/\bUPDATE\s+ct_provider_overlap_telemetry\b/i.test(helperSource));
}

console.log(`CT provider overlap telemetry: ${passed}/${passed + failed} assertions passed`);
if (failed > 0) process.exit(1);
console.log("CT provider overlap telemetry validation passed");
process.exit(0);
