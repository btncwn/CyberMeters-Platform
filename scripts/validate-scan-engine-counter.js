#!/usr/bin/env node
//
// Faithful scan-engine subrequest counter + legacy-probe-shape proof.
//
// The model harness (validate-scan-subrequest-budget.js) checks the budget math in
// isolation. This fixture runs the ACTUAL runScanEngine against mocked fetch / D1 / R2
// with a counter that observes EVERY real outbound call — so instrumentation is proven
// against the engine, not a self-agreeing model. It runs BOTH modes: the legacy ledger
// stays within its budget envelope (still legacy MODE — not switched to reserved), and
// the reserved ledger is captured faithfully. It also proves the legacy probeAsset
// result shape is unchanged; C1 hardened the redirect handling to SSRF-safe manual
// per-hop validation (so the probe now also resolves A+AAAA for the rebinding guard).
// Node 24+.
//
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const eng = (f) => import(pathToFileURL(path.join(root, "workers", "scan-api", "src", "engines", f)).href);
const { runScanEngine } = await eng("scan-engine.js");
const { probeAsset } = await eng("asset-intel.js");
const { classifyRequest } = await import(pathToFileURL(path.join(root, "scripts", "validate-scan-subrequest-budget.js")).href);

let pass = 0, fail = 0;
const ok = (n, c, d = "") => { c ? pass++ : fail++; if (!c) console.log(`FAIL ${n}${d ? " — " + d : ""}`); };
const eq = (n, g, w) => ok(n, g === w, `got ${JSON.stringify(g)} want ${JSON.stringify(w)}`);
const realFetch = globalThis.fetch;

// ── Section A: legacy probeAsset call + result shape unchanged ─────────────────
{
  let lastOpts = null;
  globalThis.fetch = async (_url, opts) => { lastOpts = opts; return new Response("<title>x</title>", { status: 200, headers: { "content-type": "text/html" } }); };
  const r = await probeAsset("up.example");
  // C1 (2026-07-19): the default prober is now SSRF-safe — it follows redirects
  // MANUALLY and validates every hop (scheme/credentials/private-reserved literal +
  // DNS-answer rebinding) via the shared makeSsrfSafeProbeFetch core. It previously
  // used native redirect:"follow" with no per-hop validation (the redirect-time SSRF).
  eq("legacy probeAsset uses SSRF-safe redirect:\"manual\" (C1)", lastOpts.redirect, "manual");
  eq("legacy probeAsset method GET", lastOpts.method, "GET");
  ok("legacy probeAsset keeps AbortSignal timeout", !!lastOpts.signal);
  ok("legacy probeAsset sets redirect:\"manual\" for per-hop SSRF validation (C1)", lastOpts.redirect === "manual");
  eq("legacy probeAsset success result shape unchanged",
     Object.keys(r).sort().join(","), "content_type,host,reachable,server,status,tech,title,url");
  globalThis.fetch = realFetch;
}

// ── Faithful engine run with an outbound counter (per mode) ───────────────────
const VARIABLE_CT_HOSTS = Array.from({ length: 300 }, (_, i) => `ct${i}.example.com`);
const VARIABLE_KNOWN_HOSTS = Array.from({ length: 50 }, (_, i) => `known${i}.example.com`);

function respond(url, {
  dmarcRua = false,
  authorizeExternal = false,
  variableFanout = false,
} = {}) {
  const cat = classifyRequest(url);
  if (cat === "doh") {
    let name = "", type = "A";
    try { const u = new URL(url); name = u.searchParams.get("name") || ""; type = u.searchParams.get("type") || "A"; } catch {}
    if (variableFanout && type === "CNAME" && /^ct\d+\.example\.com$/.test(name)) {
      return new Response(JSON.stringify({ Answer: [{ type: 5, data: "candidate.github.io" }] }), {
        status: 200,
        headers: { "content-type": "application/dns-json" },
      });
    }
    if (variableFanout && /^(?:ct|known)\d+\.example\.com$/.test(name) && (type === "A" || type === "AAAA")) {
      const Answer = type === "A"
        ? [{ type: 1, data: "93.184.216.34" }]
        : [{ type: 28, data: "2606:2800:220:1:248:1893:25c8:1946" }];
      return new Response(JSON.stringify({ Answer }), { status: 200, headers: { "content-type": "application/dns-json" } });
    }
    if (type === "A" && name === "example.com") return new Response(JSON.stringify({ Answer: [{ data: "93.184.216.34" }] }), { status: 200, headers: { "content-type": "application/dns-json" } });
    if (dmarcRua && type === "TXT" && name === "_dmarc.example.com") {
      return new Response(JSON.stringify({
        Answer: [{ type: 16, data: "v=DMARC1; p=reject; rua=mailto:agg@reports.vendor.test" }],
      }), { status: 200, headers: { "content-type": "application/dns-json" } });
    }
    if (dmarcRua && type === "TXT" && name === "_dmarc.vendor.test") {
      return new Response(JSON.stringify({
        Answer: [{ type: 16, data: "v=DMARC1; p=none; psd=n" }],
      }), { status: 200, headers: { "content-type": "application/dns-json" } });
    }
    if (authorizeExternal && type === "TXT" &&
        name === "example.com._report._dmarc.reports.vendor.test") {
      return new Response(JSON.stringify({
        Answer: [{ type: 16, data: "v=DMARC1" }],
      }), { status: 200, headers: { "content-type": "application/dns-json" } });
    }
    return new Response(JSON.stringify({ Answer: [] }), { status: 200, headers: { "content-type": "application/dns-json" } });
  }
  if (cat === "ct") {
    const rows = variableFanout
      ? VARIABLE_CT_HOSTS.map((hostname) => ({ name_value: hostname, dns_names: [hostname] }))
      : [{ name_value: "admin.example.com" }];
    return new Response(JSON.stringify(rows), { status: 200, headers: { "content-type": "application/json" } });
  }
  if (cat === "exposure") {
    if (variableFanout) {
      const parsed = new URL(url);
      const depth = Number(parsed.pathname.match(/^\/cm-bound-hop-(\d+)$/)?.[1] || 0);
      if (depth < 4) {
        return new Response("", {
          status: 302,
          headers: { location: `/cm-bound-hop-${depth + 1}` },
        });
      }
    }
    return new Response("<title>Admin</title>", { status: 200, headers: { "content-type": "text/html", server: "nginx" } });
  }
  return new Response("{}", { status: 200, headers: { "content-type": "application/json" } });
}
async function runEngineLedger(mode, {
  dmarcRua = false,
  authorizeExternal = false,
  subrequestLimit = null,
  variableFanout = false,
} = {}) {
  const counter = { total: 0, byCategory: {}, dnsQuestions: [] };
  globalThis.fetch = async (url) => {
    const s = String(url);
    counter.total += 1;
    const cat = classifyRequest(s);
    counter.byCategory[cat] = (counter.byCategory[cat] || 0) + 1;
    if (cat === "doh") {
      const u = new URL(s);
      counter.dnsQuestions.push({
        resolver: u.hostname,
        name: u.searchParams.get("name"),
        type: u.searchParams.get("type"),
        dnssec: u.searchParams.get("do") === "1",
      });
    }
    return respond(s, { dmarcRua, authorizeExternal, variableFanout });
  };
  let report = null;
  let snapshot = null;
  const r2 = new Map();
  const makeStatement = (sql, args = []) => ({
    bind: (...bound) => makeStatement(sql, bound),
    run: async () => ({
      meta: {
        changes:
          /INSERT OR IGNORE INTO scan_report_snapshots/.test(sql) ||
          /UPDATE scan_report_snapshots[\s\S]*SET status = 'completed'/.test(sql)
            ? 1
            : 0,
      },
      success: true,
    }),
    all: async () => ({
      results: variableFanout && /SELECT DISTINCT wa\.hostname/.test(sql)
        ? VARIABLE_KNOWN_HOSTS.map((hostname) => ({ hostname }))
        : [],
    }),
    first: async () => {
      if (
        /SELECT id FROM workspaces WHERE id = \? AND deleted_at IS NULL/.test(sql)
      ) {
        return { id: args[0] };
      }
      return null;
    },
  });
  const env = {
    cybermeters_db: {
      prepare: (sql) => makeStatement(sql),
      batch: async () => [],
    },
    cybermeters_reports: {
      put: async (key, body) => {
        r2.set(String(key), String(body));
        if (String(key) === `reports/scan_${mode}.json`) {
          try { report = JSON.parse(String(body)); } catch { /* malformed fixture */ }
        } else if (String(key).startsWith(
          `reports/snapshots/ws_test/scan_${mode}/`,
        )) {
          try { snapshot = JSON.parse(String(body)); } catch { /* malformed fixture */ }
        }
        return {};
      },
      get: async (key) => {
        const body = r2.get(String(key));
        return body == null ? null : {
          text: async () => body,
          json: async () => JSON.parse(body),
        };
      },
      delete: async () => ({}),
    },
    SCAN_CAPACITY_MODE: mode,
    ...(subrequestLimit == null ? {} : {
      SCAN_SUBREQUEST_LIMIT: String(subrequestLimit),
    }),
    APP_VERSION: "test",
  };
  let threw = null;
  try { await runScanEngine(`scan_${mode}`, "dom_test", "ws_test", "example.com", env); } catch (e) { threw = e; }
  globalThis.fetch = realFetch;
  return { counter, threw, report, snapshot };
}

// ── Section B: legacy engine ledger (unchanged after Commit 3) ────────────────
{
  const { counter, threw, report, snapshot } = await runEngineLedger("legacy");
  console.log(`legacy engine ledger:   total=${counter.total} ${JSON.stringify(counter.byCategory)}`);
  eq("legacy: runScanEngine completed", threw, null);
  ok("legacy: counter observed the real engine's outbound calls", counter.total > 0, `total ${counter.total}`);
  ok("legacy: observed DoH (real DNS fan-out incl. brute-force)", (counter.byCategory.doh || 0) >= 10, `doh ${counter.byCategory.doh}`);
  ok("legacy: observed HTTP(S) probe calls", (counter.byCategory.exposure || 0) > 0);
  ok("legacy: exceeds the 50-class ceiling (the root defect)", counter.total > 50, `total ${counter.total}`);
  ok("legacy: total === sum of categories", counter.total === Object.values(counter.byCategory).reduce((a, b) => a + b, 0));
  eq("legacy: real report carries DMARCbis v2 core evidence",
    report?.modules?.dmarc_core?.schema, "dmarc-policy.v2");
  eq("legacy: no-policy fixture still completes the core",
    report?.modules?.dmarc_core?.core_completeness, "complete");
  eq("legacy: zero RUA is explicitly not applicable",
    report?.modules?.dmarc_core?.rua_authorisation_completeness, "not_applicable");
  eq("legacy: compatibility projection never invents inherited/exact policy",
    report?.modules?.email_security?.dmarc?.policy, null);
  eq("legacy: outer canonical snapshot schema remains v1",
    snapshot?.snapshot?.snapshot_schema_version, "1");
  eq("legacy: real engine writes the nested DMARCbis snapshot block",
    snapshot?.protocol_evidence?.dmarc?.schema, "dmarc-policy.v2");
  ok("legacy: report protocol evidence carries a SHA-256 fingerprint",
    /^[a-f0-9]{64}$/.test(
      report?.modules?.dmarc_core?.evidence_fingerprint || "",
    ));
  eq("legacy: report and snapshot use the exact same canonical protocol object",
    JSON.stringify(snapshot?.protocol_evidence?.dmarc),
    JSON.stringify(report?.modules?.dmarc_core));
  for (const resolver of ["cloudflare-dns.com", "dns.google"]) {
    eq(
      `legacy: shared cache issues exact DMARC once to ${resolver}`,
      counter.dnsQuestions.filter((q) =>
        q.resolver === resolver &&
        q.name === "_dmarc.example.com" &&
        q.type === "TXT" &&
        q.dnssec === false).length,
      1,
    );
  }
}

// ── Section C: reserved engine ledger (faithful) ──────────────────────────────
{
  const { counter, threw, report } = await runEngineLedger("reserved");
  console.log(`reserved engine ledger: total=${counter.total} ${JSON.stringify(counter.byCategory)}`);
  if (threw) console.log(`(reserved engine returned after discovery: ${String(threw).slice(0, 80)})`);
  ok("reserved: counter observed the real engine's outbound calls", counter.total > 0, `total ${counter.total}`);
  ok("reserved: observed DoH (core DNS + critical-prefix + SSRF resolution)", (counter.byCategory.doh || 0) > 0);
  ok("reserved: observed HTTP(S) probe calls (headers/ssl/reserved exposure)", (counter.byCategory.exposure || 0) > 0);
  ok("reserved: total === sum of categories", counter.total === Object.values(counter.byCategory).reduce((a, b) => a + b, 0));
  eq("reserved: core evidence was produced before capacity deferrals",
    report?.modules?.dmarc_core?.core_completeness, "complete");
  if (!report?.modules?.dmarc_core) {
    console.log(`reserved report diagnostic: ${JSON.stringify(report)?.slice(0, 800)}`);
  }
}

// ── Section D: real engine traces for the optional RFC 9990 phase ───────────
{
  const coreOnly = await runEngineLedger("legacy", {
    dmarcRua: true,
    authorizeExternal: true,
    subrequestLimit: 50,
  });
  eq("core-only degraded trace completes runScanEngine", coreOnly.threw, null);
  eq("core-only degraded trace preserves complete core",
    coreOnly.report?.modules?.dmarc_core?.core_completeness, "complete");
  eq("core-only degraded trace marks external authorization incomplete",
    coreOnly.report?.modules?.dmarc_core?.rua_authorisation_completeness,
    "incomplete");
  eq("core-only degraded trace records deterministic subrequest refusal",
    coreOnly.report?.modules?.dmarc_core?.external_rua_authorisation
      ?.launch_gate?.reason,
    "subrequest_budget");
  eq("launch refusal issues zero RFC 9990 authorization questions",
    coreOnly.counter.dnsQuestions.filter((question) =>
      String(question.name).includes("._report._dmarc.")).length,
    0);

  const completeExternal = await runEngineLedger("legacy", {
    dmarcRua: true,
    authorizeExternal: true,
    subrequestLimit: 200,
  });
  eq("complete external trace completes runScanEngine",
    completeExternal.threw, null);
  eq("complete external trace publishes complete authorization",
    completeExternal.report?.modules?.dmarc_core
      ?.rua_authorisation_completeness,
    "complete");
  eq("complete external trace records authorized destination",
    completeExternal.report?.modules?.dmarc_core
      ?.external_rua_authorisation?.destinations?.[0]?.authorization_status,
    "authorized");
  eq("complete external trace corroborates the authorization record",
    completeExternal.counter.dnsQuestions.filter((question) =>
      String(question.name).includes("._report._dmarc.")).length,
    2);
  if (completeExternal.report?.modules?.dmarc_core
      ?.rua_authorisation_completeness !== "complete") {
    console.log("external gate diagnostic: " + JSON.stringify({
      gate: completeExternal.report?.modules?.dmarc_core
        ?.external_rua_authorisation?.launch_gate,
      telemetry: completeExternal.report?.execution_diagnostics?.modules
        ?.filter((row) => row?.outbound?.outbound_measurement_complete === false),
    }));
  }
}

// ── Section E: maximum existing host-driven fan-out remains provider-bounded ─
// This is a behavioral fixture, not a self-imposed physical 200 counter. It drives
// the real legacy engine with 300 CT hosts, 50 historical recheck hosts, the
// takeover 100-host cap, exposure 50-host cap, and the real redirect-hop guards.
// The observed call count must exceed the application admission/report value 200
// while remaining far below the authenticated Workers Paid provider ceiling 10k.
{
  const bounded = await runEngineLedger("legacy", {
    subrequestLimit: 200,
    variableFanout: true,
  });
  console.log(`legacy max-fanout ledger: total=${bounded.counter.total} ${JSON.stringify(bounded.counter.byCategory)}`);
  eq("max-fanout: real legacy engine completes", bounded.threw, null);
  eq("max-fanout: report labels 200 as effective admission/report limit",
    bounded.report?.scan_quality?.subrequest_budget?.effective_limit, 200);
  eq("max-fanout: report labels provider ceiling 10000",
    bounded.report?.scan_quality?.subrequest_budget?.platform_ceiling, 10_000);
  ok("max-fanout: legacy report has no reserved physical-counter snapshot",
    bounded.report?.modules?.scan_budget?.physical == null,
    JSON.stringify(bounded.report?.modules?.scan_budget?.physical));
  ok("max-fanout: actual outbound exceeds 200, proving it is not a physical hard cap",
    bounded.counter.total > 200, `total ${bounded.counter.total}`);
  ok("max-fanout: actual outbound remains below Paid provider ceiling 10000",
    bounded.counter.total < 10_000, `total ${bounded.counter.total}`);
  eq("max-fanout: takeover executes its existing 100-host bound",
    bounded.report?.modules?.subdomain_takeover?.totals?.checked, 100);
  eq("max-fanout: exposure executes its existing 50-host bound",
    bounded.report?.modules?.asset_exposure?.probe_coverage?.checked, 50);
  ok("max-fanout: exposure records bounded truncation rather than unbounded launch",
    bounded.report?.modules?.asset_exposure?.probe_coverage?.cap_reached === true &&
      bounded.report?.modules?.asset_exposure?.probe_coverage?.candidate_total > 50,
    JSON.stringify(bounded.report?.modules?.asset_exposure?.probe_coverage));
  ok("max-fanout: total equals the observed category ledger",
    bounded.counter.total === Object.values(bounded.counter.byCategory).reduce((a, b) => a + b, 0));
}

console.log(`\nscan-engine-counter: ${pass} passed, ${fail} failed`);
if (fail > 0) process.exit(1);
