#!/usr/bin/env node
// CT-R2 PR-2A faithful runScanEngine trace. Proves the shadow row is written
// only after terminal finalization and that D1 failure cannot change the report,
// scan status/readiness, or at-least-once idempotency.
import fs from "node:fs";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const engineUrl = pathToFileURL(path.join(
  root,
  "workers/scan-api/src/engines/scan-engine.js",
)).href;
const { runScanEngine } = await import(
  process.env.CT_OVERLAP_SCAN_ENGINE_MODULE_URL || engineUrl
);

const NOW = "2026-08-02T11:00:00.000Z";
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
    try { db.exec(fs.readFileSync(file, "utf8")); }
    catch { /* consolidated schema and historical migrations overlap */ }
  };
  apply(path.join(root, "database/schema.sql"));
  for (const file of fs.readdirSync(path.join(root, "database/migrations"))
    .filter((name) => name.endsWith(".sql")).sort()) {
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
      const isOverlapWrite = /INSERT OR IGNORE INTO ct_provider_overlap_telemetry/i.test(sql);
      if (isOverlapWrite) {
        options.overlapWriteAttempts = (options.overlapWriteAttempts || 0) + 1;
        if (options.failOverlapWrites) {
          options.overlapWriteFailureInjected = true;
          throw new Error("fixture overlap D1 database unavailable");
        }
      }
      if (
        /INSERT INTO findings/i.test(sql)
        && options.failFindingsAfterOverlap
        && options.overlapWriteAttempts > 0
        && !options.findingsFailureInjected
      ) {
        options.findingsFailureInjected = true;
        throw new Error("fixture post-overlap persistence failure");
      }
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
      const results = [];
      db.exec("BEGIN");
      try {
        for (const entry of statements) {
          results.push(/^\s*select/i.test(entry.__sql)
            ? await entry.all()
            : await entry.run());
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

function makeR2(store) {
  return {
    get: async (key) => {
      const body = store.get(String(key));
      return body == null ? null : {
        text: async () => body,
        json: async () => JSON.parse(body),
      };
    },
    put: async (key, body) => {
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

const originalFetch = globalThis.fetch;
const originalRandom = Math.random;
const originalSetTimeout = globalThis.setTimeout;
let outerReleaseMode = false;
let resolveOuterLateFetch = null;
globalThis.fetch = async (input) => {
  const url = new URL(String(input));
  if (url.hostname === "crt.sh") {
    if (outerReleaseMode) {
      return jsonResponse([{
        name_value: "example.com\ntrace.example.com",
        common_name: "example.com",
        not_before: "2026-07-01T00:00:00.000Z",
        not_after: "2030-11-01T00:00:00.000Z",
        issuer_name: "CT Outer Release Fixture CA",
      }]);
    }
    return jsonResponse({}, 403);
  }
  if (url.hostname === "api.certspotter.com") {
    if (outerReleaseMode) {
      return await new Promise((resolve) => {
        resolveOuterLateFetch = () => resolve(jsonResponse([{
          id: "ct-overlap-late-certspotter",
          not_before: "2026-07-01T00:00:00.000Z",
          not_after: "2030-11-01T00:00:00.000Z",
          issuer: { name: "CT Outer Release Fixture CA" },
          dns_names: ["example.com", "late.example.com"],
        }]));
      });
    }
    return jsonResponse([{
      id: "ct-overlap-certspotter",
      not_before: "2026-07-01T00:00:00.000Z",
      not_after: "2026-11-01T00:00:00.000Z",
      issuer: { name: "CT Overlap Fixture CA" },
      dns_names: ["example.com", "www.example.com", "trace.example.com"],
    }]);
  }
  if (url.hostname === "cloudflare-dns.com" || url.hostname === "dns.google") {
    const name = String(url.searchParams.get("name") || "").toLowerCase();
    const type = String(url.searchParams.get("type") || "A").toUpperCase();
    if (name === "example.com" && type === "A") {
      return jsonResponse({ Status: 0, Answer: [{ type: 1, data: "93.184.216.34" }] });
    }
    return jsonResponse({ Status: 0, Answer: [] });
  }
  return new Response("<html><title>Example</title></html>", {
    status: 200,
    headers: { "content-type": "text/html", server: "ct-overlap-engine-trace" },
  });
};
Math.random = () => 0.123456789;

function createFixture(options = {}) {
  const db = buildDb();
  const sequence = [];
  const store = new Map();
  const env = {
    cybermeters_db: makeD1(db, sequence, options),
    cybermeters_reports: makeR2(store),
    SCAN_CAPACITY_MODE: "legacy",
    SCAN_SUBREQUEST_LIMIT: "200",
    SCAN_DEADLINE_MS: "19000",
    APP_VERSION: "ct-overlap-engine-trace",
  };
  db.prepare("INSERT INTO users (id, email) VALUES ('usr', 'owner@example.com')").run();
  db.prepare("INSERT INTO workspaces (id, name, deleted_at) VALUES ('ws', 'CT overlap', NULL)").run();
  db.prepare("INSERT INTO domains (id, user_id, domain) VALUES ('dom', 'usr', 'example.com')").run();
  db.prepare("INSERT INTO workspace_domains (workspace_id, domain_id) VALUES ('ws', 'dom')").run();
  db.prepare(`INSERT INTO scans
    (id, workspace_id, domain_id, domain, status, scan_quality, created_at)
    VALUES ('scan-overlap', 'ws', 'dom', 'example.com', 'running', NULL, ?)`)
    .run(NOW);
  return { db, sequence, store, env, options };
}

async function execute(options = {}, { outerRelease = false } = {}) {
  const fixture = createFixture(options);
  let engineError = null;
  outerReleaseMode = outerRelease;
  resolveOuterLateFetch = null;
  if (outerRelease) {
    // Preserve the real race ordering: launch the subdomains work first, then
    // make only its 12s outer cap release on the next task turn.
    globalThis.setTimeout = (callback, delay, ...args) => delay === 12_000
      ? originalSetTimeout(callback, 0, ...args)
      : originalSetTimeout(callback, delay, ...args);
  }
  try {
    await runScanEngine(
      "scan-overlap",
      "dom",
      "ws",
      "example.com",
      fixture.env,
      { now: () => NOW_MS, executionContext: "queue", trigger: "manual" },
    );
  } catch (error) {
    engineError = error;
  } finally {
    globalThis.setTimeout = originalSetTimeout;
    outerReleaseMode = false;
  }
  return { ...fixture, engineError, resolveOuterLateFetch };
}

try {
  const completed = await execute();
  eq("engine trace: runScanEngine completes", completed.engineError, null);
  eq("engine trace: terminal scan is completed",
    completed.db.prepare("SELECT status FROM scans WHERE id='scan-overlap'").get()?.status,
    "completed");
  const reportBytes = completed.store.get("reports/scan-overlap.json");
  ok("engine trace: terminal report is ready", typeof reportBytes === "string");
  const report = JSON.parse(reportBytes || "{}");
  const terminalCustomerResult = (value) => JSON.stringify({
    status: value?.status,
    cyber_metrics_score: value?.cyber_metrics_score,
    risk_level: value?.risk_level,
    scan_quality: value?.scan_quality,
    subdomains: value?.modules?.subdomains,
  });
  eq("engine trace: customer subdomain result survives shadow measurement",
    report.modules?.subdomains?.items?.includes("trace.example.com"), true);
  eq("engine trace: existing scan quality is unchanged",
    report.scan_quality?.status, "partial");
  const row = completed.db.prepare(
    "SELECT * FROM ct_provider_overlap_telemetry WHERE scan_id='scan-overlap'",
  ).get();
  ok("engine trace: exactly one durable overlap row exists", Boolean(row));
  eq("engine trace: provider failure censors comparison",
    row?.comparison_status, "censored_provider_failure");
  eq("engine trace: censored overlap fields remain NULL",
    [row?.intersection_count, row?.crt_sh_only_count,
      row?.certspotter_only_count, row?.union_count]
      .every((value) => value === null), true);
  const terminalIndex = completed.sequence.findIndex((entry) =>
    /UPDATE scans SET status = \?, score = \?, rating = \?, scan_quality = \?/i.test(entry.sql)
      && entry.args[0] === "completed");
  const overlapIndexes = completed.sequence
    .map((entry, index) => ({ entry, index }))
    .filter(({ entry }) => /INSERT OR IGNORE INTO ct_provider_overlap_telemetry/i.test(entry.sql))
    .map(({ index }) => index);
  ok("engine trace: overlap write occurs only after terminal D1 finalization",
    terminalIndex >= 0 && overlapIndexes.length === 1
      && overlapIndexes.every((index) => index > terminalIndex));

  const failureOptions = { failOverlapWrites: true };
  const persistenceFailure = await execute(failureOptions);
  eq("persistence failure: controlled D1 failure is injected",
    failureOptions.overlapWriteFailureInjected, true);
  eq("persistence failure: runScanEngine still returns normally",
    persistenceFailure.engineError, null);
  eq("persistence failure: terminal scan remains completed",
    persistenceFailure.db.prepare("SELECT status FROM scans WHERE id='scan-overlap'").get()?.status,
    "completed");
  eq("persistence failure: terminal customer result is byte-identical",
    terminalCustomerResult(JSON.parse(
      persistenceFailure.store.get("reports/scan-overlap.json") || "{}",
    )), terminalCustomerResult(report));
  eq("persistence failure: no partial/synthetic overlap row remains",
    persistenceFailure.db.prepare(
      "SELECT COUNT(*) AS n FROM ct_provider_overlap_telemetry WHERE scan_id='scan-overlap'",
    ).get()?.n, 0);
  ok("persistence failure: scan never remains running",
    persistenceFailure.db.prepare("SELECT status FROM scans WHERE id='scan-overlap'").get()?.status
      !== "running");

  // Force the already-finalized catch path. The once-only in-memory guard and
  // durable UNIQUE gate must not attempt or create a second overlap row.
  const repeatedOptions = { failFindingsAfterOverlap: true };
  const repeated = await execute(repeatedOptions);
  eq("repeated finalization: post-overlap failure is injected",
    repeatedOptions.findingsFailureInjected, true);
  eq("repeated finalization: completed state is preserved",
    repeated.db.prepare("SELECT status FROM scans WHERE id='scan-overlap'").get()?.status,
    "completed");
  eq("repeated finalization: one durable row remains",
    repeated.db.prepare(
      "SELECT COUNT(*) AS n FROM ct_provider_overlap_telemetry WHERE scan_id='scan-overlap'",
    ).get()?.n, 1);
  eq("repeated finalization: overlap insert attempted once",
    repeatedOptions.overlapWriteAttempts, 1);

  // The scan-engine's 12s consumer cap is shorter than the subdomains module's
  // 15s cap. One provider is terminal and the other is still running when the
  // outer consumer releases; persistence must use that exact frozen state.
  const outerRelease = await execute({}, { outerRelease: true });
  eq("outer 12s release: runScanEngine completes", outerRelease.engineError, null);
  const outerRow = outerRelease.db.prepare(
    "SELECT * FROM ct_provider_overlap_telemetry WHERE scan_id='scan-overlap'",
  ).get();
  eq("outer 12s release: frozen provider states are durable",
    `${outerRow?.crt_sh_attempt_state}|${outerRow?.certspotter_attempt_state}|${outerRow?.comparison_status}`,
    "terminal_success|in_flight_at_consumer_release|censored_in_flight");
  eq("outer 12s release: overlap fields remain NULL",
    [outerRow?.intersection_count, outerRow?.crt_sh_only_count,
      outerRow?.certspotter_only_count, outerRow?.union_count]
      .every((value) => value === null), true);
  outerRelease.resolveOuterLateFetch?.();
  await Promise.resolve();
  await Promise.resolve();
  const durableAfterLate = outerRelease.db.prepare(
    "SELECT * FROM ct_provider_overlap_telemetry WHERE scan_id='scan-overlap'",
  ).get();
  eq("outer 12s release: late provider settlement cannot rewrite durable state",
    `${durableAfterLate?.certspotter_attempt_state}|${durableAfterLate?.comparison_status}`,
    "in_flight_at_consumer_release|censored_in_flight");
} finally {
  globalThis.fetch = originalFetch;
  Math.random = originalRandom;
  globalThis.setTimeout = originalSetTimeout;
}

console.log(`CT provider overlap engine trace: ${passed}/${passed + failed} assertions passed`);
if (failed > 0) process.exit(1);
console.log("CT provider overlap engine trace passed");
process.exit(0);
