#!/usr/bin/env node
// CT-R1 faithful runScanEngine trace: provider rows are terminal-finalization-only,
// bounded, correctly attributed, non-behavioural, and outside the 19s envelope.
import fs from "node:fs";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const defaultEngineUrl = pathToFileURL(path.join(
  root,
  "workers/scan-api/src/engines/scan-engine.js"
)).href;
const { runScanEngine } = await import(
  process.env.CT_R1_SCAN_ENGINE_MODULE_URL || defaultEngineUrl
);
const { analyzeCtProviderTelemetry } = await import(pathToFileURL(path.join(
  root,
  "scripts/analyze-ct-provider-telemetry.js"
)).href);

const NOW = "2026-07-27T13:00:00.000Z";
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

function buildDb() {
  const db = new DatabaseSync(":memory:");
  const apply = (file) => {
    try {
      db.exec(fs.readFileSync(file, "utf8"));
    } catch {
      // The historical schema and convergent migrations intentionally overlap.
    }
  };
  apply(path.join(root, "database/schema.sql"));
  for (const file of fs.readdirSync(path.join(root, "database/migrations"))
    .filter((name) => name.endsWith(".sql"))
    .sort()) {
    apply(path.join(root, "database/migrations", file));
  }
  db.exec("PRAGMA foreign_keys = OFF");
  return db;
}

function makeD1(db, sequence, options = {}) {
  const statement = (sql, args = []) => ({
    __sql: sql,
    bind: (...bound) => statement(sql, bound),
    first: async (column) => {
      const row = db.prepare(sql).get(...args) ?? null;
      return column && row ? row[column] : row;
    },
    all: async () => ({
      results: db.prepare(sql).all(...args),
      success: true,
      meta: {},
    }),
    run: async () => {
      sequence.push({ sql, args });
      const isCtWrite = /INSERT INTO ct_provider_telemetry/i.test(sql);
      if (isCtWrite) {
        options.ctWriteAttempts = (options.ctWriteAttempts || 0) + 1;
        if (
          options.failCtWrites
          || options.ctWriteAttempts === options.failCtWriteAtIndex
        ) {
          options.ctWriteFailureInjected = true;
          throw new Error("fixture CT telemetry D1 failure");
        }
      }
      if (
        /INSERT INTO findings/i.test(sql)
        && options.failFindingsAfterCtWrite
        && options.ctWriteObserved
        && !options.findingsFailureInjected
      ) {
        options.findingsFailureInjected = true;
        throw new Error("fixture post-finalize failure");
      }
      const result = db.prepare(sql).run(...args);
      if (isCtWrite) options.ctWriteObserved = true;
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
      const results = [];
      db.exec("BEGIN");
      try {
        for (const entry of statements) {
          results.push(
            /^\s*select/i.test(entry.__sql)
              ? await entry.all()
              : await entry.run()
          );
        }
        db.exec("COMMIT");
        return results;
      } catch (error) {
        db.exec("ROLLBACK");
        throw error;
      }
    },
  };
}

function makeR2(store, options = {}) {
  return {
    get: async (key) => {
      const body = store.get(String(key));
      return body == null ? null : {
        text: async () => body,
        json: async () => JSON.parse(body),
      };
    },
    put: async (key, body) => {
      options.putAttempts = (options.putAttempts || 0) + 1;
      if (options.failFirstPut && options.putAttempts === 1) {
        options.firstPutFailureInjected = true;
        throw new Error("fixture first terminal R2 failure");
      }
      store.set(String(key), String(body));
      return {};
    },
    delete: async (key) => {
      store.delete(String(key));
      return {};
    },
    head: async () => null,
    list: async () => ({ objects: [] }),
  };
}

const jsonResponse = (body, status = 200) => new Response(JSON.stringify(body), {
  status,
  headers: { "content-type": "application/json" },
});

const providerCalls = { crt_sh: 0, certspotter: 0 };
const originalFetch = globalThis.fetch;
const originalRandom = Math.random;
globalThis.fetch = async (input) => {
  const url = new URL(String(input));
  if (url.hostname === "crt.sh") {
    providerCalls.crt_sh += 1;
    return jsonResponse({}, 403);
  }
  if (url.hostname === "api.certspotter.com") {
    providerCalls.certspotter += 1;
    return jsonResponse([{
      id: "ct-r1-certspotter",
      not_before: "2026-07-01T00:00:00.000Z",
      not_after: "2026-11-01T00:00:00.000Z",
      issuer: { name: "CT-R1 Fixture CA" },
      dns_names: ["example.com", "www.example.com", "trace.example.com"],
    }]);
  }
  if (url.hostname === "cloudflare-dns.com" || url.hostname === "dns.google") {
    const name = String(url.searchParams.get("name") || "").toLowerCase();
    const type = String(url.searchParams.get("type") || "A").toUpperCase();
    if (name === "example.com" && type === "A") {
      return jsonResponse({
        Status: 0,
        Answer: [{ type: 1, data: "93.184.216.34" }],
      });
    }
    return jsonResponse({ Status: 0, Answer: [] });
  }
  return new Response("<html><title>Example</title></html>", {
    status: 200,
    headers: {
      "content-type": "text/html",
      server: "ct-r1-engine-trace",
    },
  });
};
Math.random = () => 0.123456789;

function createTraceFixture(options = {}) {
  const db = buildDb();
  const sequence = [];
  const store = new Map();
  const env = {
    cybermeters_db: makeD1(db, sequence, options),
    cybermeters_reports: makeR2(store, options),
    SCAN_CAPACITY_MODE: "legacy",
    SCAN_SUBREQUEST_LIMIT: "200",
    SCAN_DEADLINE_MS: "19000",
    APP_VERSION: "ct-r1-engine-trace",
  };

  db.prepare("INSERT INTO users (id, email) VALUES ('usr', 'owner@example.com')").run();
  db.prepare(
    "INSERT INTO workspaces (id, name, deleted_at) VALUES ('ws', 'CT-R1', NULL)"
  ).run();
  db.prepare(
    "INSERT INTO domains (id, user_id, domain) VALUES ('dom', 'usr', 'example.com')"
  ).run();
  db.prepare(
    "INSERT INTO workspace_domains (workspace_id, domain_id) VALUES ('ws', 'dom')"
  ).run();
  db.prepare(
    `INSERT INTO scans
      (id, workspace_id, domain_id, domain, status, scan_quality, created_at)
     VALUES ('scan-ct-r1', 'ws', 'dom', 'example.com', 'running', NULL, ?)`
  ).run(NOW);
  return { db, sequence, store, env, options };
}

async function executeTrace(options = {}) {
  const fixture = createTraceFixture(options);
  let engineError = null;
  try {
    await runScanEngine(
      "scan-ct-r1",
      "dom",
      "ws",
      "example.com",
      fixture.env,
      {
        now: () => NOW_MS,
        executionContext: "queue",
        trigger: "manual",
      }
    );
  } catch (error) {
    engineError = error;
  }
  return { ...fixture, engineError };
}

function analyzeTrace(db) {
  const rows = db.prepare(
    `SELECT
       s.id AS scan_id,
       s.scan_quality,
       s.created_at AS scan_created_at,
       t.module,
       t.provider,
       t.outcome,
       t.http_status,
       t.latency_ms,
       t.result_count,
       t.started_at,
       t.completed_at,
       t.completeness_impact,
       t.affected_signal,
       t.cache_state,
       t.cache_age_s
     FROM scans AS s
     LEFT JOIN ct_provider_telemetry AS t ON t.scan_id = s.id
     WHERE s.id = 'scan-ct-r1'`
  ).all();
  return analyzeCtProviderTelemetry(rows, { nowMs: NOW_MS });
}

try {
  const completedTrace = await executeTrace();
  const { db, sequence, store, engineError } = completedTrace;

  eq("real runScanEngine completes", engineError, null);
  eq("real engine finalizes completed",
    db.prepare("SELECT status FROM scans WHERE id = 'scan-ct-r1'").get()?.status,
    "completed");
  eq("pre-existing single shared crt.sh request remains unchanged",
    providerCalls.crt_sh, 1);
  eq("pre-existing single shared CertSpotter request remains unchanged",
    providerCalls.certspotter, 1);

  const rawReport = store.get("reports/scan-ct-r1.json");
  ok("real engine writes terminal report", typeof rawReport === "string");
  const report = JSON.parse(rawReport || "{}");
  eq("existing failure still produces partial quality",
    report.scan_quality?.status, "partial");
  eq("existing subdomain result survives telemetry",
    report.modules?.subdomains?.items?.includes("trace.example.com"), true);
  eq("existing CertSpotter certificate result survives telemetry",
    report.modules?.ssl?.cert_issuer, "CT-R1 Fixture CA");
  eq("19-second executable envelope remains intact",
    report.execution_diagnostics?.deadline_budget_ms, 19_000);
  const sslDiagnostic = (report.execution_diagnostics?.modules || [])
    .find((row) => row.module === "ssl");
  eq("SSL allocation remains exactly nine seconds",
    sslDiagnostic?.allocated_ms, 9_000);

  const rows = db.prepare(
    `SELECT module, provider, outcome, http_status, latency_ms, result_count,
            completeness_impact, affected_signal, cache_state, cache_age_s
     FROM ct_provider_telemetry
     WHERE scan_id = 'scan-ct-r1'
     ORDER BY provider, module`
  ).all();
  eq("real engine writes four consumer-attributed rows", rows.length, 4);
  ok("real engine respects eight-row hard bound", rows.length <= 8);
  eq("crt.sh classified as HTTP error",
    rows.filter((row) => row.provider === "crt_sh")
      .every((row) => row.outcome === "http_error" && row.http_status === 403),
    true);
  eq("CertSpotter classified ok with count",
    rows.filter((row) => row.provider === "certspotter")
      .every((row) => row.outcome === "ok" && row.result_count === 1),
    true);
  eq("only subdomain crt.sh row carries completeness impact",
    rows.filter((row) => row.completeness_impact === 1)
      .map((row) => `${row.module}:${row.provider}:${row.affected_signal}`)
      .join(","),
    "subdomains:crt_sh:subdomain_discovery");
  eq("R1 cache columns remain inert",
    rows.every((row) => row.cache_state === "miss" && row.cache_age_s === null),
    true);
  const completedAnalysis = analyzeTrace(db);
  eq("fully persisted scan reads measured",
    completedAnalysis.telemetry_coverage.measurement_state, "measured");
  eq("fully persisted scan reads 100 percent covered",
    completedAnalysis.telemetry_coverage.telemetry_coverage_pct, 100);

  const terminalIndex = sequence.findIndex((entry) =>
    /UPDATE scans SET status = \?, score = \?, rating = \?, scan_quality = \?/i
      .test(entry.sql) &&
    entry.args[0] === "completed"
  );
  const ctWriteIndexes = sequence
    .map((entry, index) => ({ entry, index }))
    .filter(({ entry }) => /INSERT INTO ct_provider_telemetry/i.test(entry.sql))
    .map(({ index }) => index);
  ok("terminal D1 finalization is observed", terminalIndex >= 0);
  ok("all CT writes occur after terminal finalization",
    ctWriteIndexes.length > 0 &&
    ctWriteIndexes.every((index) => index > terminalIndex));

  // A terminal failure after genuine CT attempts must retain those attempts.
  const failedOptions = { failFirstPut: true };
  const failedTrace = await executeTrace(failedOptions);
  eq("failed-terminal trace does not throw", failedTrace.engineError, null);
  eq("failed-terminal trace injects terminal persistence failure",
    failedOptions.firstPutFailureInjected, true);
  eq("failed-terminal trace leaves scan durably failed",
    failedTrace.db.prepare(
      "SELECT status FROM scans WHERE id = 'scan-ct-r1'"
    ).get()?.status,
    "failed");
  const failedRows = failedTrace.db.prepare(
    "SELECT * FROM ct_provider_telemetry WHERE scan_id = 'scan-ct-r1'"
  ).all();
  eq("failed-terminal trace persists CT provider rows", failedRows.length, 4);
  ok("failed-terminal trace respects eight-row bound", failedRows.length <= 8);
  ok("failed-terminal trace does not leave scan running",
    failedTrace.db.prepare(
      "SELECT status FROM scans WHERE id = 'scan-ct-r1'"
    ).get()?.status !== "running");
  const failedTerminalIndex = failedTrace.sequence.findIndex((entry) =>
    /UPDATE scans SET status = \?, score = \?, rating = \?, scan_quality = \?/i
      .test(entry.sql) &&
    entry.args[0] === "failed"
  );
  const failedCtIndexes = failedTrace.sequence
    .map((entry, index) => ({ entry, index }))
    .filter(({ entry }) => /INSERT INTO ct_provider_telemetry/i.test(entry.sql))
    .map(({ index }) => index);
  ok("failed-terminal CT writes occur after failed status write",
    failedTerminalIndex >= 0 &&
    failedCtIndexes.length > 0 &&
    failedCtIndexes.every((index) => index > failedTerminalIndex));

  // Force the catch path after completed finalization and the first CT snapshot
  // has been written. The once-only guard must suppress a second set.
  const onceOnlyOptions = { failFindingsAfterCtWrite: true };
  const onceOnlyTrace = await executeTrace(onceOnlyOptions);
  eq("finalize-then-catch fixture injects its failure",
    onceOnlyOptions.findingsFailureInjected, true);
  eq("finalize-then-catch preserves completed terminal state",
    onceOnlyTrace.db.prepare(
      "SELECT status FROM scans WHERE id = 'scan-ct-r1'"
    ).get()?.status,
    "completed");
  eq("finalize-then-catch returns without throwing",
    onceOnlyTrace.engineError, null);
  eq("finalize-then-catch persists exactly one CT row set",
    onceOnlyTrace.db.prepare(
      "SELECT COUNT(*) AS n FROM ct_provider_telemetry WHERE scan_id = 'scan-ct-r1'"
    ).get()?.n,
    rows.length);
  eq("finalize-then-catch attempts exactly one CT row set",
    onceOnlyTrace.sequence.filter((entry) =>
      /INSERT INTO ct_provider_telemetry/i.test(entry.sql)
    ).length,
    rows.length);

  // D1 telemetry failure on the failed terminal path remains observational.
  const telemetryFailureOptions = { failFirstPut: true, failCtWrites: true };
  const telemetryFailureTrace = await executeTrace(telemetryFailureOptions);
  eq("failed-path telemetry write failure is injected",
    telemetryFailureOptions.ctWriteFailureInjected, true);
  eq("failed-path telemetry write failure does not throw",
    telemetryFailureTrace.engineError, null);
  eq("failed-path telemetry write failure preserves failed terminal state",
    telemetryFailureTrace.db.prepare(
      "SELECT status FROM scans WHERE id = 'scan-ct-r1'"
    ).get()?.status,
    "failed");
  ok("failed-path telemetry write failure does not leave scan running",
    telemetryFailureTrace.db.prepare(
      "SELECT status FROM scans WHERE id = 'scan-ct-r1'"
    ).get()?.status !== "running");

  // D1 batch is mirrored as an explicit SQLite transaction in makeD1. Fail the
  // second statement after the first insert ran: rollback must leave zero rows,
  // and the analyzer must not describe this scan as measured/100%.
  const atomicFailureOptions = { failCtWriteAtIndex: 2 };
  const atomicFailureTrace = await executeTrace(atomicFailureOptions);
  eq("controlled single-row batch failure is injected",
    atomicFailureOptions.ctWriteFailureInjected, true);
  eq("atomic telemetry batch failure does not throw",
    atomicFailureTrace.engineError, null);
  eq("atomic telemetry batch failure preserves completed terminal state",
    atomicFailureTrace.db.prepare(
      "SELECT status FROM scans WHERE id = 'scan-ct-r1'"
    ).get()?.status,
    "completed");
  eq("atomic telemetry batch failure rolls back every CT row",
    atomicFailureTrace.db.prepare(
      "SELECT COUNT(*) AS n FROM ct_provider_telemetry WHERE scan_id = 'scan-ct-r1'"
    ).get()?.n,
    0);
  const atomicFailureAnalysis = analyzeTrace(atomicFailureTrace.db);
  eq("rolled-back CT snapshot reads not measured",
    atomicFailureAnalysis.telemetry_coverage.measurement_state, "not_measured");
  eq("rolled-back CT snapshot reads zero percent covered",
    atomicFailureAnalysis.telemetry_coverage.telemetry_coverage_pct, 0);
  eq("rolled-back completion loss remains unattributed",
    atomicFailureAnalysis.telemetry_coverage.completion_loss_unattributed, 1);
} finally {
  globalThis.fetch = originalFetch;
  Math.random = originalRandom;
}

console.log(
  `CT-R1 runScanEngine trace: ${passed}/${passed + failed} assertions passed`
);
if (failed > 0) process.exit(1);
console.log("CT-R1 runScanEngine trace passed");
process.exit(0);
