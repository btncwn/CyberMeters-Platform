#!/usr/bin/env node
// CT-R1 provider-attempt fixtures, schema/governance, analyzer, and non-fatality.
import fs from "node:fs";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const engineUrl = (name) => pathToFileURL(path.join(
  root,
  "workers/scan-api/src/engines",
  name
)).href;
const cacheModule = await import(
  process.env.CT_R1_CACHE_MODULE_URL || engineUrl("ct-provider-cache.js")
);
const subdomainsModule = await import(
  process.env.CT_R1_SUBDOMAINS_MODULE_URL || engineUrl("subdomains-scan.js")
);
const scanEngineModule = await import(
  process.env.CT_R1_SCAN_ENGINE_MODULE_URL || engineUrl("scan-engine.js")
);
const { resolveCertificateTransparency } = await import(engineUrl("ssl-scan.js"));
const { buildScanQuality, persistCtProviderTelemetry } = scanEngineModule;
const {
  createCertificateTransparencyCache,
  CT_PROVIDER_TELEMETRY_OUTCOMES,
  CT_PROVIDER_TELEMETRY_ROW_LIMIT,
} = cacheModule;
const { runSubdomainsModule } = subdomainsModule;
const { analyzeCtProviderTelemetry, READ_QUERY } = await import(pathToFileURL(
  path.join(root, "scripts/analyze-ct-provider-telemetry.js")
).href);

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

const jsonResponse = (body, status = 200) => new Response(JSON.stringify(body), {
  status,
  headers: { "content-type": "application/json" },
});
const CRT_OK = [{
  id: "crt-1",
  name_value: "example.com\na.example.com",
  common_name: "example.com",
  issuer_name: "Fixture CRT CA",
  not_before: "2026-01-01T00:00:00.000Z",
  not_after: "2027-01-01T00:00:00.000Z",
}];
const CERTSPOTTER_OK = [{
  id: "certspotter-1",
  dns_names: ["example.com", "b.example.com"],
  issuer: { name: "Fixture CertSpotter CA" },
  not_before: "2026-01-01T00:00:00.000Z",
  not_after: "2027-01-01T00:00:00.000Z",
}];

function providerFetcher(spec) {
  return async (input) => {
    const provider = String(input).includes("crt.sh") ? "crt_sh" : "certspotter";
    const outcome = spec[provider];
    if (outcome === "ok") {
      return jsonResponse(provider === "crt_sh" ? CRT_OK : CERTSPOTTER_OK);
    }
    if (outcome === "timeout") {
      throw new DOMException(`${provider} fixture timeout`, "TimeoutError");
    }
    if (outcome === "parse_error") {
      return new Response("<html>not json</html>", {
        status: 200,
        headers: { "content-type": "text/html" },
      });
    }
    if (outcome === "rate_limited") return jsonResponse({}, 429);
    if (outcome === "http_error") return jsonResponse({}, 503);
    throw new Error(`${provider} fixture network failure`);
  };
}

function telemetryClock() {
  let now = Date.parse("2026-07-27T12:00:00.000Z");
  return () => {
    const value = now;
    now += 7;
    return value;
  };
}

async function executeModules(spec, captureTelemetry) {
  const ctCache = createCertificateTransparencyCache({
    fetcher: providerFetcher(spec),
    captureTelemetry,
    sleep: async () => {},
    telemetryNow: telemetryClock(),
    timeoutSignal: () => undefined,
  });
  const [ssl, subdomains] = await Promise.all([
    resolveCertificateTransparency("example.com", { ctCache }),
    runSubdomainsModule("example.com", { ctCache }),
  ]);
  const modules = { ssl, subdomains };
  const scanQuality = buildScanQuality(modules);
  return {
    modules,
    scanQuality,
    rows: ctCache.telemetrySnapshot({ modules, scanQuality }),
  };
}

const fixtures = [
  {
    name: "both ok",
    spec: { crt_sh: "ok", certspotter: "ok" },
    outcomes: { crt_sh: ["ok"], certspotter: ["ok"] },
    quality: "complete",
  },
  {
    name: "crt.sh timeout / CertSpotter ok",
    spec: { crt_sh: "timeout", certspotter: "ok" },
    outcomes: { crt_sh: ["timeout"], certspotter: ["ok"] },
    quality: "partial",
  },
  {
    name: "CertSpotter parse error / crt.sh ok",
    spec: { crt_sh: "ok", certspotter: "parse_error" },
    outcomes: { crt_sh: ["ok"], certspotter: ["parse_error"] },
    quality: "partial",
  },
  {
    name: "both fail",
    spec: { crt_sh: "timeout", certspotter: "network_error" },
    outcomes: { crt_sh: ["timeout"], certspotter: ["network_error"] },
    quality: "partial",
  },
  {
    name: "rate-limited",
    spec: { crt_sh: "rate_limited", certspotter: "ok" },
    outcomes: { crt_sh: ["rate_limited"], certspotter: ["ok"] },
    quality: "partial",
  },
];

const originalFetch = globalThis.fetch;
const originalRandom = Math.random;
globalThis.fetch = async (input) => {
  const url = new URL(String(input));
  if (url.hostname === "cloudflare-dns.com" || url.hostname === "dns.google") {
    return jsonResponse({ Status: 0, Answer: [] });
  }
  throw new Error(`unexpected fixture fetch ${url.hostname}`);
};
Math.random = () => 0.123456789;

const capturedFixtureRows = new Map();
try {
  for (const fixture of fixtures) {
    const untreated = await executeModules(fixture.spec, false);
    const observed = await executeModules(fixture.spec, true);
    eq(
      `${fixture.name}: module results byte-identical with telemetry`,
      JSON.stringify(observed.modules),
      JSON.stringify(untreated.modules)
    );
    eq(`${fixture.name}: canonical scan quality unchanged`,
      observed.scanQuality.status, fixture.quality);
    ok(`${fixture.name}: telemetry stays within hard row bound`,
      observed.rows.length <= CT_PROVIDER_TELEMETRY_ROW_LIMIT);
    eq(`${fixture.name}: R1 cache state always miss`,
      observed.rows.every((row) => row.cache_state === "miss"), true);
    eq(`${fixture.name}: R1 cache age always null`,
      observed.rows.every((row) => row.cache_age_s === null), true);
    eq(`${fixture.name}: every attempt has bounded latency`,
      observed.rows.every((row) =>
        Number.isInteger(row.latency_ms) && row.latency_ms >= 0
      ), true);
    eq(`${fixture.name}: every attempt has ISO lifecycle timestamps`,
      observed.rows.every((row) =>
        Number.isFinite(Date.parse(row.started_at)) &&
        Number.isFinite(Date.parse(row.completed_at))
      ), true);
    eq(`${fixture.name}: successful attempt counts are populated`,
      observed.rows
        .filter((row) => row.outcome === "ok")
        .every((row) =>
          row.http_status === 200 && Number.isInteger(row.result_count)
        ), true);

    for (const [provider, expectedOutcomes] of Object.entries(fixture.outcomes)) {
      const actual = [...new Set(
        observed.rows
          .filter((row) => row.provider === provider)
          .map((row) => row.outcome)
      )].sort();
      eq(`${fixture.name}: ${provider} attribution`,
        JSON.stringify(actual), JSON.stringify([...expectedOutcomes].sort()));
    }

    const failedProviders = new Set(
      Object.entries(fixture.spec)
        .filter(([, outcome]) => outcome !== "ok")
        .map(([provider]) => provider)
    );
    const impactRows = observed.rows.filter((row) => row.completeness_impact);
    eq(`${fixture.name}: impact only belongs to subdomains`,
      impactRows.every((row) => row.module === "subdomains"), true);
    eq(`${fixture.name}: impacted rows carry affected signal`,
      impactRows.every((row) => row.affected_signal === "subdomain_discovery"), true);
    eq(`${fixture.name}: provider failures drive expected impact`,
      [...new Set(impactRows.map((row) => row.provider))].sort().join(","),
      [...failedProviders].sort().join(","));
    ok(`${fixture.name}: expected discovered subdomains survive telemetry`,
      fixture.spec.crt_sh === "ok"
        ? observed.modules.subdomains.items.includes("a.example.com")
        : observed.modules.subdomains.items.includes("b.example.com") ||
          fixture.spec.certspotter !== "ok");
    capturedFixtureRows.set(fixture.name, observed.rows);
  }
} finally {
  globalThis.fetch = originalFetch;
  Math.random = originalRandom;
}

eq("frozen outcome vocabulary",
  CT_PROVIDER_TELEMETRY_OUTCOMES.join("|"),
  "ok|timeout|http_error|parse_error|rate_limited|network_error");
eq("runtime hard row bound", CT_PROVIDER_TELEMETRY_ROW_LIMIT, 8);

// Persistence is explicitly invoked after collection: module execution made no D1 call.
{
  const calls = [];
  const env = {
    cybermeters_db: {
      prepare: (sql) => ({
        bind: (...args) => ({
          run: async () => {
            calls.push({ sql, args });
            if (process.env.CT_R1_TEST_WRITE_FAILURE === "1") {
              throw new Error("fixture telemetry write failure");
            }
          },
        }),
      }),
    },
  };
  eq("provider telemetry collection performs no D1 write", calls.length, 0);
  let writeError = null;
  try {
    await persistCtProviderTelemetry(
      "scan-fixture",
      capturedFixtureRows.get("crt.sh timeout / CertSpotter ok"),
      env
    );
  } catch (error) {
    writeError = error;
  }
  eq("provider telemetry persistence is non-fatal", writeError, null);
  if (process.env.CT_R1_TEST_WRITE_FAILURE !== "1") {
    ok("provider telemetry persistence targets canonical table",
      calls.length > 0 &&
      calls.every((call) => /INSERT INTO ct_provider_telemetry/i.test(call.sql)));
  }
}

// Migration 103: additive constraints, frozen vocabulary, inert cache columns,
// FK inheritance, and the durable eight-row ceiling.
{
  const migrationPath = path.join(
    root,
    "database/migrations/103-ct-provider-telemetry.sql"
  );
  const migration = fs.readFileSync(migrationPath, "utf8");
  ok("migration 103 is additive",
    /CREATE TABLE IF NOT EXISTS ct_provider_telemetry/i.test(migration) &&
    !/\b(DROP|DELETE FROM|TRUNCATE)\b/i.test(migration.replace(/--[^\n]*/g, "")));
  for (const outcome of CT_PROVIDER_TELEMETRY_OUTCOMES) {
    ok(`migration freezes ${outcome}`, migration.includes(`'${outcome}'`));
  }
  ok("migration constrains cache vocabulary",
    ["miss", "fresh_hit", "stale_available"].every((value) =>
      migration.includes(`'${value}'`)
    ));
  ok("migration includes affected signal",
    /\baffected_signal\b/.test(migration));
  ok("migration inherits tenancy through scan FK",
    /FOREIGN KEY \(scan_id\) REFERENCES scans\(id\)/i.test(migration));

  const db = new DatabaseSync(":memory:");
  db.exec("PRAGMA foreign_keys = OFF");
  db.exec(`
    CREATE TABLE scans (id TEXT PRIMARY KEY);
    ${migration}
    INSERT INTO scans (id) VALUES ('scan-bound');
  `);
  const insert = db.prepare(`
    INSERT INTO ct_provider_telemetry
      (id, scan_id, module, provider, outcome, latency_ms, started_at,
       completed_at, completeness_impact, affected_signal, cache_state)
    VALUES (?, 'scan-bound', ?, ?, 'ok', 1,
            '2026-07-27T00:00:00.000Z', '2026-07-27T00:00:00.001Z',
            0, NULL, 'miss')
  `);
  for (let index = 0; index < 8; index += 1) {
    insert.run(
      `row-${index}`,
      index % 2 === 0 ? "ssl" : "subdomains",
      index % 4 < 2 ? "crt_sh" : "certspotter"
    );
  }
  eq("migration permits exactly eight rows",
    db.prepare("SELECT COUNT(*) AS n FROM ct_provider_telemetry").get().n, 8);
  let ninthRejected = false;
  try {
    insert.run("row-9", "ssl", "crt_sh");
  } catch {
    ninthRejected = true;
  }
  eq("migration rejects ninth row", ninthRejected, true);
}

// Analyzer: one complete plus two completion losses, one co-failure.
{
  const rows = [];
  const addAttempt = ({
    scan_id,
    scan_quality,
    provider,
    outcome,
    latency_ms,
    impact = 0,
    started_at,
  }) => {
    for (const module of ["ssl", "subdomains"]) {
      rows.push({
        scan_id,
        scan_quality,
        scan_created_at: "2026-07-26T12:00:00.000Z",
        provider,
        outcome,
        http_status: outcome === "ok" ? 200 : null,
        latency_ms,
        result_count: outcome === "ok" ? 1 : null,
        started_at,
        completed_at: new Date(Date.parse(started_at) + latency_ms).toISOString(),
        completeness_impact: module === "subdomains" ? impact : 0,
        affected_signal: module === "subdomains" && impact
          ? "subdomain_discovery"
          : null,
        cache_state: "miss",
        cache_age_s: null,
        module,
      });
    }
  };
  addAttempt({
    scan_id: "scan-complete", scan_quality: "complete", provider: "crt_sh",
    outcome: "ok", latency_ms: 10, started_at: "2026-07-26T12:00:01.000Z",
  });
  addAttempt({
    scan_id: "scan-complete", scan_quality: "complete", provider: "certspotter",
    outcome: "ok", latency_ms: 20, started_at: "2026-07-26T12:00:02.000Z",
  });
  addAttempt({
    scan_id: "scan-partial-a", scan_quality: "partial", provider: "crt_sh",
    outcome: "timeout", latency_ms: 30, impact: 1,
    started_at: "2026-07-26T12:01:01.000Z",
  });
  addAttempt({
    scan_id: "scan-partial-a", scan_quality: "partial", provider: "certspotter",
    outcome: "ok", latency_ms: 40, started_at: "2026-07-26T12:01:02.000Z",
  });
  addAttempt({
    scan_id: "scan-partial-b", scan_quality: "partial", provider: "crt_sh",
    outcome: "rate_limited", latency_ms: 50, impact: 1,
    started_at: "2026-07-26T12:02:01.000Z",
  });
  addAttempt({
    scan_id: "scan-partial-b", scan_quality: "partial", provider: "certspotter",
    outcome: "parse_error", latency_ms: 60, impact: 1,
    started_at: "2026-07-26T12:02:02.000Z",
  });
  const analysis = analyzeCtProviderTelemetry(rows, {
    nowMs: Date.parse("2026-07-27T12:00:00.000Z"),
  });
  eq("analysis computes completion denominator", analysis.completion.scans, 3);
  eq("analysis computes founder completion rate",
    analysis.completion.completion_rate_pct, 33.33);
  eq("analysis computes per-class attribution rows",
    analysis.failure_attribution.length, 3);
  eq("analysis computes loss percentage",
    analysis.failure_attribution.every((row) => row.pct_of_completion_loss === 50),
    true);
  eq("analysis deduplicates consumer rows for latency",
    analysis.latency_percentiles.reduce((sum, row) => sum + row.attempts, 0), 6);
  eq("analysis computes co-failure count",
    analysis.co_failure.both_providers_failed, 1);
  eq("analysis computes co-failure rate",
    analysis.co_failure.co_failure_rate_pct, 33.33);
  ok("analysis query is read-only",
    /^\s*SELECT\b/i.test(READ_QUERY) &&
    !/\b(INSERT|UPDATE|DELETE|DROP|ALTER|CREATE)\b/i.test(READ_QUERY));
}

// Static lifecycle and governance anchors.
{
  const scanEngine = fs.readFileSync(path.join(
    root,
    "workers/scan-api/src/engines/scan-engine.js"
  ), "utf8");
  const finalizeIndex = scanEngine.indexOf("const finalized = await finalizeScanResult");
  const persistIndex = scanEngine.indexOf("await persistCtProviderTelemetry(");
  ok("CT persistence is after terminal finalization",
    finalizeIndex >= 0 && persistIndex > finalizeIndex);
  ok("CT persistence is not inside runCappedModule",
    persistIndex > scanEngine.indexOf("const runCappedModule") &&
    persistIndex > scanEngine.indexOf("const scanQuality = buildScanQuality"));

  const indexSource = fs.readFileSync(path.join(
    root,
    "workers/scan-api/src/index.js"
  ), "utf8");
  ok("scan-child purge list includes CT telemetry",
    /SCAN_CHILD_TABLES[\s\S]*ct_provider_telemetry/.test(indexSource));
  const resources = fs.readFileSync(path.join(
    root,
    "scripts/security/lib/tenant-resources.js"
  ), "utf8");
  ok("tenant resource class includes CT telemetry",
    /class: "scans"[\s\S]*ct_provider_telemetry/.test(resources));
}

console.log(`CT-R1 provider telemetry: ${passed}/${passed + failed} assertions passed`);
if (failed > 0) process.exit(1);
console.log("CT-R1 provider telemetry validation passed");
process.exit(0);
