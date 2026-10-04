#!/usr/bin/env node
// C4: run real certificate consumers with a July scan clock and a November
// process clock. All I/O is in-memory; the process clock advances normally.
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const RealDate = Date;
const realFetch = globalThis.fetch;
const offset = RealDate.parse("2026-11-01T00:00:00.000Z") - RealDate.now();
globalThis.Date = class extends RealDate {
  constructor(...args) { super(...(args.length ? args : [RealDate.now() + offset])); }
  static now() { return RealDate.now() + offset; }
};
const NOW = "2026-07-27T13:00:00.000Z";
const NOW_MS = Date.parse(NOW);
const EXPIRY = "2026-11-01T00:00:00.000Z";
const START = "2026-07-01T00:00:00.000Z";
const DAY = 86_400_000;
let passed = 0;
let failed = 0;
async function test(name, run) {
  try { await run(); passed++; console.log(`PASS ${name}`); }
  catch (error) {
    failed++;
    console.error(`${error.code === "ERR_ASSERTION" ? "FAIL" : "INSTRUMENT_ERROR"} ${name}: ${error.stack}`);
  }
}

try {
  const { resolveCertificateTransparency } = await import("../workers/scan-api/src/engines/ssl-scan.js");
  const { buildCertificateTrustL2 } = await import("../workers/scan-api/src/engines/cert-trust-l2.js");
  const { runScanEngine } = await import("../workers/scan-api/src/engines/scan-engine.js");
  const { insertCertificateEvents } = await import("../workers/scan-api/src/engines/cert-events.js");

  function cache(provider, expiry = EXPIRY) {
    return { get: async (_domain, requested) => ({
      status: requested === provider ? "available" : "unavailable",
      error: requested === provider ? null : "fixture unavailable",
      data: requested !== provider ? null : [{
        not_before: START, not_after: expiry,
        common_name: "example.com", name_value: "example.com\nadmin.example.com",
        issuer_name: "C4 CA", issuer: { name: "C4 CA" },
        dns_names: ["example.com", "admin.example.com"],
      }],
    }) };
  }
  // No live fetch is permitted, even on an unexpected branch.
  globalThis.fetch = async (input) => {
    const url = new URL(String(input));
    const json = (body, status = 200) => new Response(JSON.stringify(body), {
      status, headers: { "content-type": "application/json" },
    });
    if (url.hostname === "crt.sh") return json({}, 403);
    if (url.hostname === "api.certspotter.com") return json([{
      not_before: START, not_after: EXPIRY, issuer: { name: "C4 CA" },
      dns_names: ["example.com", "admin.example.com"],
    }]);
    if (["cloudflare-dns.com", "dns.google"].includes(url.hostname)) {
      return json({ Status: 0, Answer: url.searchParams.get("type") === "A"
        && url.searchParams.get("name") === "example.com"
        ? [{ type: 1, data: "93.184.216.34" }] : [] });
    }
    return new Response("<html><title>Example</title></html>", {
      headers: { "content-type": "text/html" },
    });
  };

  for (const provider of ["crt_sh", "certspotter"]) {
    await test(`C4 ${provider}: injected instant selects certificate; strict boundary`, async () => {
      let calls = 0;
      const selected = await resolveCertificateTransparency("example.com", {
        ctCache: cache(provider), now: () => { calls++; return NOW_MS + (calls - 1) * DAY; },
      });
      assert.equal(selected.cert_not_after, EXPIRY, "injected July clock must retain November certificate");
      assert.equal(calls, 1, "resolver samples injected clock exactly once");
      assert.equal(selected.cert_expiry_days, Math.floor((Date.parse(EXPIRY) - NOW_MS) / DAY));
      assert.equal(selected.cert_age_days, Math.floor((NOW_MS - Date.parse(START)) / DAY));
      const equal = await resolveCertificateTransparency("example.com", {
        ctCache: cache(provider), now: () => Date.parse(EXPIRY),
      });
      assert.equal(equal.cert_not_after, null, "not_after == now must remain excluded");
      const defaultClock = await resolveCertificateTransparency("example.com", { ctCache: cache(provider) });
      assert.equal(defaultClock.cert_not_after, null, "default November clock excludes expired certificate");
      if (provider === "certspotter") {
        // Both providers answer, but crt.sh has no unexpired certificate. The
        // fallback must use the first instant even if the clock would advance.
        calls = 0;
        const mixed = { get: (domain, source) => cache(source, source === "crt_sh" ? NOW : EXPIRY).get(domain, source) };
        const fallback = await resolveCertificateTransparency("example.com", {
          ctCache: mixed, now: () => { calls++; return NOW_MS + (calls - 1) * DAY; },
        });
        assert.equal(calls, 1, "crt.sh and CertSpotter fallback share one sampled instant");
        assert.equal(fallback.cert_not_after, EXPIRY);
        assert.equal(fallback.cert_expiry_days, Math.floor((Date.parse(EXPIRY) - NOW_MS) / DAY));
      }
    });
  }

  await test("C4 trust L2: injected read instant and wall-clock default", () => {
    const cert = { expires_at: "2026-07-29T13:00:00.000Z", issuer: "C4 CA", subject: "example.com" };
    const injected = buildCertificateTrustL2(cert, { nowMs: NOW_MS });
    assert.equal(injected.trust_path.expiry_ok, true, "L2 trust path must use injected read instant");
    assert.equal(injected.renewal_readiness.days_remaining, 2, "L2 readiness must use same read instant");
    assert.equal(injected.findings.find(f => f.type === "expiring_soon")?.evidence[0].days_until_expiry, 2);
    assert.equal(buildCertificateTrustL2(cert).trust_path.expiry_ok, false, "default L2 remains read-time");
    assert.equal(buildCertificateTrustL2(cert, { nowMs: NaN }).trust_path.expiry_ok, false);
    assert.equal(buildCertificateTrustL2({ ...cert, days_until_expiry: 7 }, { nowMs: NOW_MS })
      .renewal_readiness.days_remaining, 7, "precomputed finite days retain precedence");
  });

  // The established engine-trace D1/R2 fixture pattern: real schema + convergent
  // migrations in :memory:, with no persistent database or real service binding.
  const db = new DatabaseSync(":memory:");
  const apply = file => { try { db.exec(fs.readFileSync(file, "utf8")); } catch { /* convergent */ } };
  apply(path.join(root, "database/schema.sql"));
  for (const f of fs.readdirSync(path.join(root, "database/migrations")).filter(f => f.endsWith(".sql")).sort()) {
    apply(path.join(root, "database/migrations", f));
  }
  db.exec("PRAGMA foreign_keys = OFF");
  const writes = [];
  const statement = (sql, args = []) => ({
    __sql: sql, bind: (...bound) => statement(sql, bound),
    first: async column => { const row = db.prepare(sql).get(...args) ?? null; return column && row ? row[column] : row; },
    all: async () => ({ results: db.prepare(sql).all(...args), success: true, meta: {} }),
    run: async () => {
      writes.push({ sql, args });
      const result = db.prepare(sql).run(...args);
      return { success: true, meta: { changes: result.changes, last_row_id: Number(result.lastInsertRowid || 0) } };
    },
  });
  const objects = new Map();
  const env = {
    cybermeters_db: { prepare: sql => statement(sql), batch: entries => Promise.all(entries.map(e => /^\s*select/i.test(e.__sql) ? e.all() : e.run())) },
    cybermeters_reports: {
      get: async key => objects.has(key) ? { text: async () => objects.get(key), json: async () => JSON.parse(objects.get(key)) } : null,
      put: async (key, body) => { objects.set(key, String(body)); return {}; },
      delete: async key => { objects.delete(key); }, head: async () => null, list: async () => ({ objects: [] }),
    },
    SCAN_CAPACITY_MODE: "legacy", SCAN_SUBREQUEST_LIMIT: "200", SCAN_DEADLINE_MS: "115000", APP_VERSION: "c4-clock-regression",
  };
  db.exec("INSERT INTO users (id,email) VALUES ('c4-user','owner@example.com'); INSERT INTO workspaces (id,name) VALUES ('c4-ws','C4'); INSERT INTO domains (id,user_id,domain) VALUES ('c4-domain','c4-user','example.com'); INSERT INTO workspace_domains (workspace_id,domain_id) VALUES ('c4-ws','c4-domain')");
  db.prepare("INSERT INTO scans (id,workspace_id,domain_id,domain,status,created_at) VALUES ('c4-scan','c4-ws','c4-domain','example.com','running',?)").run(NOW);
  await runScanEngine("c4-scan", "c4-domain", "c4-ws", "example.com", env, {
    now: () => NOW_MS, executionContext: "queue", trigger: "manual",
  });
  const reports = [...objects.values()].map(v => { try { return JSON.parse(v); } catch { return null; } });
  const report = reports.find(r => r?.modules?.certificate_intelligence);
  await test("C4 engine: CT and cert-intel share evaluation instant", () => {
    assert.ok(report, "engine must persist a report");
    assert.equal(report.modules.ssl.cert_not_after, EXPIRY, "engine must pass scan clock to SSL");
    assert.equal(report.modules.certificate_intelligence.expiry_evidence, "usable", "cert-intel must use CT evaluation instant");
  });
  await test("C4 engine: observation producer and lifecycle consumer share scan time", () => {
    const observation = db.prepare("SELECT * FROM certificate_observations WHERE workspace_id='c4-ws'").get();
    assert.ok(observation, "scan must persist certificate observation");
    assert.equal(observation.first_seen, NOW, "certificate observation must use scan clock");
    assert.equal(observation.last_seen, NOW);
    const lifecycle = db.prepare("SELECT * FROM certificate_lifecycle WHERE workspace_id='c4-ws'").get();
    assert.ok(lifecycle, "scan must correlate certificate lifecycle");
    assert.equal(lifecycle.created_at, NOW, "lifecycle must use scan clock");
    assert.equal(lifecycle.updated_at, NOW);
  });

  // A separate comparable-report fixture isolates event timestamps from CT
  // selection failure. It does not change the engine trace's quality or evidence.
  await test("C4 certificate events: injected production time", async () => {
    const cert = { issuer: "C4 CA", subject: "example.com", issued_for_sensitive_hosts: [], days_until_expiry: 5, expires_at: "2026-08-01T13:00:00.000Z" };
    const current = { scan_quality: { status: "complete" }, timeline_trust: { asset_timeline_producer_version: "asset-timeline-trust-v1" }, modules: { certificate_intelligence: cert } };
    db.prepare("INSERT INTO scans (id,workspace_id,domain_id,domain,status,scan_quality,created_at) VALUES ('c4-event-baseline','c4-ws','c4-domain','example.com','completed','complete',?)").run("2026-07-27T13:30:00.000Z");
    objects.set("reports/c4-event-baseline.json", JSON.stringify({ ...current, modules: { certificate_intelligence: { ...cert, days_until_expiry: 60 } } }));
    db.prepare("INSERT INTO scans (id,workspace_id,domain_id,domain,status,scan_quality,created_at) VALUES ('c4-next','c4-ws','c4-domain','example.com','running','complete',?)").run("2026-07-27T14:00:00.000Z");
    const before = writes.length;
    await insertCertificateEvents("c4-next", "c4-domain", cert, env, { currentReport: current, now: () => NOW_MS });
    const events = writes.slice(before).filter(w => /INSERT.*asset_events/is.test(w.sql));
    assert.ok(events.length > 0, "comparable certificate event must be emitted");
    assert.ok(events.every(e => e.args.includes(NOW)), "certificate events must use injected scan clock");
  });
  db.close();
} finally {
  globalThis.Date = RealDate;
  globalThis.fetch = realFetch;
}
console.log(`C4 certificate clock: ${passed} passed, ${failed} failed`);
process.exitCode = failed ? 1 : 0;
