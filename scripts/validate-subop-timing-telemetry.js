#!/usr/bin/env node
//
// Track B — per-sub-operation timing telemetry (measurement only, NO behaviour change).
//
// Attributes a module-cap exhaustion inside ssl / headers / subdomains to the
// specific sub-operation (which HTTPS probe, which redirect hop, which CT wait):
// which one, how long, and whether it completed, was unavailable, or was aborted
// in flight. Rows persist as scan_module_telemetry pseudo-rows with dotted module
// names (the existing "scan_finalisation" no-schema pattern).
//
// This suite proves:
//   • collector contract — begin/finish rows, dotted names, bounded row count,
//     first-finish-wins, unfinished-at-snapshot reads `aborted`, clock fail-safety
//   • ssl / headers / subdomains record the expected sub-operation rows
//   • FAIL-SAFE (mutation-grade): a throwing collector, and an absent collector,
//     leave every module result deep-equal — telemetry can never alter behaviour
//   • a module abandoned by raceModuleDeadline leaves its in-flight sub-operation
//     attributable as `aborted` with elapsed time
//   • crt.sh still in flight at the cap surfaces ssl.ct_lookup as `aborted`
//     while fallback CertSpotter never starts and post-cap probes produce no telemetry row
//   • persistModuleTelemetry binds sub-op rows through the EXISTING insert path,
//     non-fatally, using only existing columns
//   • the engine wiring (subOps passed to the three offenders + snapshot persist)
//     is present in source, so it cannot be silently unwired
//
// Node 24+. CI-blocking.
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const moduleOverrides = {
  "scan-budget.js": process.env.SUBOP_TIMING_SCAN_BUDGET_MODULE_URL,
  "scan-engine.js": process.env.SUBOP_TIMING_SCAN_ENGINE_MODULE_URL,
  "ssl-scan.js": process.env.SUBOP_TIMING_SSL_MODULE_URL,
};
const eng = (f) => import(
  moduleOverrides[f]
  || pathToFileURL(path.join(root, "workers", "scan-api", "src", "engines", f)).href
);
const {
  createSubOperationTelemetry,
  SUB_OPERATION_TELEMETRY_ROW_LIMIT,
  SUB_OPERATION_TELEMETRY_OUTCOMES,
  raceModuleDeadline,
} = await eng("scan-budget.js");
const { persistSubOperationTelemetry } = await eng("scan-engine.js");
const { runSslModule } = await eng("ssl-scan.js");
const { runHeadersModule } = await eng("headers-scan.js");
const { runSubdomainsModule } = await eng("subdomains-scan.js");
const { createCertificateTransparencyCache } = await eng("ct-provider-cache.js");

const EXPECTED_ASSERTIONS = 76;
let pass = 0, fail = 0;
const ok = (n, c, d = "") => { c ? pass++ : fail++; if (!c) console.log(`FAIL ${n}${d ? " — " + d : ""}`); };
const eq = (n, g, w) => ok(n, g === w, `got ${JSON.stringify(g)} want ${JSON.stringify(w)}`);

function steppingClock(start = 1_000_000, step = 25) {
  let t = start;
  return () => { const v = t; t += step; return v; };
}

async function withMockFetch(fn, impl) {
  const prior = globalThis.fetch;
  globalThis.fetch = impl;
  try { return await fn(); }
  finally { globalThis.fetch = prior; }
}

async function withCapturedConsoleError(fn) {
  const prior = console.error;
  const errors = [];
  console.error = (...args) => { errors.push(args.map((arg) => String(arg)).join(" ")); };
  try { return { value: await fn(), errors }; }
  finally { console.error = prior; }
}

const jsonResponse = (body, init = {}) =>
  new Response(JSON.stringify(body), { status: init.status || 200, headers: { "content-type": "application/json", ...(init.headers || {}) } });

// A collector whose every method throws — the mutation the fail-safe contract
// must survive without any observable module-result difference.
const hostileCollector = () => ({
  begin() { throw new Error("hostile begin"); },
  finish() { throw new Error("hostile finish"); },
  snapshotRows() { throw new Error("hostile snapshot"); },
});

const rowsByModule = (rows) => Object.fromEntries(rows.map((r) => [r.module, r]));

// Deterministic normalizer: strip wall-clock fields that legitimately differ
// between two runs (observed_at) before deep comparison.
const normalize = (v) => JSON.parse(JSON.stringify(v, (k, val) => (k === "observed_at" ? "<t>" : val)));
const deepEq = (n, a, b) => ok(n, JSON.stringify(normalize(a)) === JSON.stringify(normalize(b)),
  "module result changed under telemetry mutation");

// ── 1. Collector contract ────────────────────────────────────────────────────
{
  const sub = createSubOperationTelemetry(steppingClock());
  const t = sub.begin("ssl", "https_probe_bare");
  sub.finish(t, { outcome: "ok" });
  const rows = sub.snapshotRows();
  eq("row count after one begin/finish", rows.length, 1);
  eq("dotted module name", rows[0].module, "ssl.https_probe_bare");
  eq("outcome ok", rows[0].outcome, "ok");
  ok("duration positive from stepping clock", rows[0].duration_ms > 0, String(rows[0].duration_ms));
  ok("started_at ISO", /^\d{4}-\d{2}-\d{2}T/.test(rows[0].started_at));
  ok("completed_at ISO when finished", /^\d{4}-\d{2}-\d{2}T/.test(rows[0].completed_at));
  eq("no outbound_calls fabricated", rows[0].outbound_calls, null);
}
{
  const sub = createSubOperationTelemetry(steppingClock());
  const t = sub.begin("ssl", "x");
  sub.finish(t, { outcome: "not_a_real_outcome" });
  eq("unknown outcome fails closed to error", sub.snapshotRows()[0].outcome, "error");
  const t2 = sub.begin("ssl", "y");
  sub.finish(t2, { outcome: "ok", aborted: true });
  eq("aborted flag wins over outcome", sub.snapshotRows()[1].outcome, "aborted");
}
{
  const sub = createSubOperationTelemetry(steppingClock());
  sub.begin("subdomains", "ct_wait_crt_sh"); // never finished
  const rows = sub.snapshotRows();
  eq("unfinished at snapshot reads aborted", rows[0].outcome, "aborted");
  eq("unfinished has null completed_at", rows[0].completed_at, null);
  ok("unfinished still carries elapsed time", rows[0].duration_ms > 0);
}
{
  const sub = createSubOperationTelemetry(steppingClock());
  const t = sub.begin("ssl", "z");
  sub.finish(t, { outcome: "ok" });
  sub.finish(t, { outcome: "error" });
  eq("first finish wins", sub.snapshotRows()[0].outcome, "ok");
}
{
  const sub = createSubOperationTelemetry(steppingClock());
  for (let i = 0; i < SUB_OPERATION_TELEMETRY_ROW_LIMIT + 10; i++) sub.begin("ssl", `op_${i}`);
  eq("row count bounded", sub.snapshotRows().length, SUB_OPERATION_TELEMETRY_ROW_LIMIT);
  eq("begin past the bound returns null", sub.begin("ssl", "overflow"), null);
}
{
  const sub = createSubOperationTelemetry(() => { throw new Error("broken clock"); });
  const t = sub.begin("ssl", "clocked");
  sub.finish(t, { outcome: "ok" });
  ok("broken clock never throws and still rows", sub.snapshotRows().length === 1);
  eq("empty names refused", createSubOperationTelemetry().begin("", ""), null);
  ok("outcome vocabulary is frozen and bounded",
    Array.isArray(SUB_OPERATION_TELEMETRY_OUTCOMES) && SUB_OPERATION_TELEMETRY_OUTCOMES.length === 4);
}

// ── Fixture fetch impls ──────────────────────────────────────────────────────
// Healthy site: bare HTTPS answers 200; plain HTTP 301s straight to HTTPS;
// both CT providers answer valid empty JSON; DoH answers NOERROR/empty.
const healthyFetch = async (url) => {
  const u = String(url);
  if (u.includes("cloudflare-dns.com")) return jsonResponse({ Status: 0, Answer: [] });
  if (u.includes("crt.sh") || u.includes("certspotter")) return jsonResponse([]);
  if (u.startsWith("http://")) {
    return new Response(null, { status: 301, headers: { location: u.replace("http://", "https://") } });
  }
  return new Response(null, { status: 200 });
};
// Bare host unreachable (thrown → safeFetch null), www answers; CT still fine.
const bareDownFetch = async (url) => {
  const u = String(url);
  if (u.includes("cloudflare-dns.com")) return jsonResponse({ Status: 0, Answer: [] });
  if (u.includes("crt.sh") || u.includes("certspotter")) return jsonResponse([]);
  if (u.startsWith("https://www.")) return new Response(null, { status: 200 });
  if (u.startsWith("http://")) return new Response(null, { status: 200 });
  throw new Error("connect timeout");
};

const FIXTURE_DOMAIN = "fixture-subop.example.com";
const sslOpts = (extra = {}) => ({
  ctCache: createCertificateTransparencyCache({ fetcher: globalThis.fetch }),
  ...extra,
});

// ── 2. ssl module records the expected sub-operations ───────────────────────
{
  const sub = createSubOperationTelemetry();
  await withMockFetch(() => runSslModule(FIXTURE_DOMAIN, sslOpts({ subOps: sub })), healthyFetch);
  const by = rowsByModule(sub.snapshotRows());
  ok("ssl.ct_lookup recorded", by["ssl.ct_lookup"]?.outcome === "ok", JSON.stringify(by["ssl.ct_lookup"]));
  eq("ssl.https_probe_bare ok", by["ssl.https_probe_bare"]?.outcome, "ok");
  eq("ssl.http_redirect_hop_1 ok", by["ssl.http_redirect_hop_1"]?.outcome, "ok");
  ok("no www probe when bare proved transport", !("ssl.https_probe_www" in by));
  ok("no hop 2 on a direct http→https redirect", !("ssl.http_redirect_hop_2" in by));
}
{
  const sub = createSubOperationTelemetry();
  await withMockFetch(() => runSslModule(FIXTURE_DOMAIN, sslOpts({ subOps: sub })), bareDownFetch);
  const by = rowsByModule(sub.snapshotRows());
  eq("bare probe unavailable when fetch fails", by["ssl.https_probe_bare"]?.outcome, "unavailable");
  eq("www fallback probe recorded ok", by["ssl.https_probe_www"]?.outcome, "ok");
}

// ── 3. ssl fail-safe: throwing / absent collector never changes the result ──
{
  const bare = await withMockFetch(() => runSslModule(FIXTURE_DOMAIN, sslOpts()), healthyFetch);
  const withCollector = await withMockFetch(
    () => runSslModule(FIXTURE_DOMAIN, sslOpts({ subOps: createSubOperationTelemetry() })), healthyFetch);
  const hostileAttempt = await withMockFetch(
    () => runSslModule(FIXTURE_DOMAIN, sslOpts({ subOps: hostileCollector() }))
      .then((value) => ({ value, error: null }), (error) => ({ value: null, error })),
    healthyFetch,
  );
  deepEq("ssl result identical with collector", withCollector, bare);
  ok(
    "ssl result identical with THROWING collector",
    hostileAttempt.error == null
      && JSON.stringify(normalize(hostileAttempt.value)) === JSON.stringify(normalize(bare)),
    hostileAttempt.error?.message || "module result changed under telemetry mutation",
  );
}

// ── 4. headers module records the expected sub-operations + fail-safe ───────
{
  const sub = createSubOperationTelemetry();
  await withMockFetch(() => runHeadersModule(FIXTURE_DOMAIN, { subOps: sub }), healthyFetch);
  const by = rowsByModule(sub.snapshotRows());
  eq("headers.probe_get_https ok", by["headers.probe_get_https"]?.outcome, "ok");
  eq("headers.probe_head_www recorded", by["headers.probe_head_www"]?.outcome, "ok");
  ok("no http fallback probe when https answered", !("headers.probe_get_http" in by));

  const bare = await withMockFetch(() => runHeadersModule(FIXTURE_DOMAIN, {}), healthyFetch);
  const withHostile = await withMockFetch(
    () => runHeadersModule(FIXTURE_DOMAIN, { subOps: hostileCollector() }), healthyFetch);
  deepEq("headers result identical with THROWING collector", withHostile, bare);
}

// ── 5. subdomains module records DNS + CT-wait sub-operations + fail-safe ───
{
  const sub = createSubOperationTelemetry();
  await withMockFetch(
    () => runSubdomainsModule(FIXTURE_DOMAIN, {
      ctCache: createCertificateTransparencyCache({ fetcher: globalThis.fetch }),
      subOps: sub,
    }),
    healthyFetch,
  );
  const by = rowsByModule(sub.snapshotRows());
  eq("subdomains.wildcard_dns_a ok", by["subdomains.wildcard_dns_a"]?.outcome, "ok");
  eq("subdomains.wildcard_dns_aaaa ok", by["subdomains.wildcard_dns_aaaa"]?.outcome, "ok");
  eq("subdomains.ct_wait_crt_sh ok", by["subdomains.ct_wait_crt_sh"]?.outcome, "ok");
  eq("subdomains.ct_wait_certspotter ok", by["subdomains.ct_wait_certspotter"]?.outcome, "ok");
}
{
  // Provider unavailable resolves (never rejects) — the wait row must say so.
  const downCtFetch = async (url) => {
    const u = String(url);
    if (u.includes("cloudflare-dns.com")) return jsonResponse({ Status: 0, Answer: [] });
    if (u.includes("crt.sh") || u.includes("certspotter")) return new Response("err", { status: 503 });
    return new Response(null, { status: 200 });
  };
  const sub = createSubOperationTelemetry();
  await withMockFetch(
    () => runSubdomainsModule(FIXTURE_DOMAIN, {
      ctCache: createCertificateTransparencyCache({ fetcher: globalThis.fetch, policies: { crt_sh: { maxAttempts: 1 }, certspotter: { maxAttempts: 1 } } }),
      subOps: sub,
    }),
    downCtFetch,
  );
  const by = rowsByModule(sub.snapshotRows());
  eq("ct_wait_crt_sh honest on provider failure", by["subdomains.ct_wait_crt_sh"]?.outcome, "unavailable");

  const bare = await withMockFetch(
    () => runSubdomainsModule(FIXTURE_DOMAIN, { ctCache: createCertificateTransparencyCache({ fetcher: globalThis.fetch }) }),
    healthyFetch,
  );
  const withHostile = await withMockFetch(
    () => runSubdomainsModule(FIXTURE_DOMAIN, { ctCache: createCertificateTransparencyCache({ fetcher: globalThis.fetch }), subOps: hostileCollector() }),
    healthyFetch,
  );
  const stripHost = (r) => ({ ...r, wildcard_test_host: "<host>" }); // random per-run label
  deepEq("subdomains result identical with THROWING collector", stripHost(withHostile), stripHost(bare));
}

// ── 5b. ssl ct_lookup is classified from ct_sources, never from bare resolve ─
{
  // Both providers down: resolveCertificateTransparency still RESOLVES with a
  // structured object — the composite lookup must read `unavailable`, not `ok`.
  const downCtFetch = async (url) => {
    const u = String(url);
    if (u.includes("crt.sh") || u.includes("certspotter")) return new Response("err", { status: 503 });
    if (u.startsWith("http://")) return new Response(null, { status: 301, headers: { location: u.replace("http://", "https://") } });
    return new Response(null, { status: 200 });
  };
  const sub = createSubOperationTelemetry();
  await withMockFetch(
    () => runSslModule(FIXTURE_DOMAIN, {
      ctCache: createCertificateTransparencyCache({ fetcher: globalThis.fetch, policies: { crt_sh: { maxAttempts: 1 }, certspotter: { maxAttempts: 1 } } }),
      subOps: sub,
    }),
    downCtFetch,
  );
  eq("ct_lookup honest when every provider failed", rowsByModule(sub.snapshotRows())["ssl.ct_lookup"]?.outcome, "unavailable");
}

// ── 6. Race-cap abort: correct attribution, and NO row for post-cap probes ───
// The fixture genuinely responds to AbortSignal — a never-resolving promise
// models a hang, not an abort, and hid exactly this defect class. Abort reaches
// the in-flight fetch the same way it does live: through accounting.signal.
{
  const abortAwareFetch = (url, init) => {
    const u = String(url);
    if (u.includes("crt.sh") || u.includes("certspotter")) return Promise.resolve(jsonResponse([]));
    return new Promise((resolve, reject) => {
      const signal = init?.signal;
      const abort = () => reject(new DOMException("The operation was aborted", "AbortError"));
      if (signal?.aborted) return abort();
      signal?.addEventListener("abort", abort, { once: true });
    });
  };
  const fakeDeadline = { remainingMs: () => 60_000 };
  const raceAborted = async (runModule, fetchImpl = abortAwareFetch) => {
    const controller = new AbortController();
    return withMockFetch(async () => {
      let modulePromise = null;
      const raced = await raceModuleDeadline(
        fakeDeadline,
        () => { modulePromise = runModule(controller); return modulePromise; },
        () => { controller.abort("module_budget_exhausted"); return { outcome: "deadline_exceeded" }; },
        { hardMs: 40 },
      );
      // Settle the abandoned module BEFORE the mock fetch is restored, exactly
      // as the live engine leaves it running detached after the race returns.
      await modulePromise?.catch(() => {});
      return raced;
    }, fetchImpl);
  };

  const sslSub = createSubOperationTelemetry();
  const sslRaced = await raceAborted((controller) => runSslModule(FIXTURE_DOMAIN, {
    ctCache: createCertificateTransparencyCache({ fetcher: globalThis.fetch }),
    signal: controller.signal,
    accounting: { signal: controller.signal },
    subOps: sslSub,
  }));
  eq("ssl race returned the deadline fallback", sslRaced?.outcome, "deadline_exceeded");
  const sslBy = rowsByModule(sslSub.snapshotRows());
  eq("ct_lookup that finished pre-cap reads ok", sslBy["ssl.ct_lookup"]?.outcome, "ok");
  eq("in-flight bare probe attributed as aborted", sslBy["ssl.https_probe_bare"]?.outcome, "aborted");
  ok("aborted probe carries elapsed time", sslBy["ssl.https_probe_bare"]?.duration_ms >= 0);
  ok("NO row for the post-cap www probe", !("ssl.https_probe_www" in sslBy), JSON.stringify(sslBy["ssl.https_probe_www"]));
  ok("NO row for the post-cap redirect hop 1", !("ssl.http_redirect_hop_1" in sslBy));
  ok("NO row for the post-cap redirect hop 2", !("ssl.http_redirect_hop_2" in sslBy));

  const headersSub = createSubOperationTelemetry();
  const headersRaced = await raceAborted((controller) => runHeadersModule(FIXTURE_DOMAIN, {
    signal: controller.signal,
    accounting: { signal: controller.signal },
    subOps: headersSub,
  }));
  eq("headers race returned the deadline fallback", headersRaced?.outcome, "deadline_exceeded");
  const headersBy = rowsByModule(headersSub.snapshotRows());
  eq("in-flight headers GET attributed as aborted", headersBy["headers.probe_get_https"]?.outcome, "aborted");
  ok("NO row for the post-cap http protocol retry", !("headers.probe_get_http" in headersBy));
  ok("NO row for the post-cap www variant", !("headers.probe_head_www" in headersBy));

  // The original corrective scenario follows the real sequential CT flow:
  // crt.sh and the concurrent bare HTTPS probe are genuinely in flight when the
  // module cap fires; CertSpotter is a fallback and must never start after that
  // external abort. Every started fetch receives the same accounting.signal used
  // by live safeFetch and rejects with AbortError. A fixture that lets crt.sh
  // complete before the cap cannot pin ct_lookup=aborted.
  const startedAbortUrls = [];
  const sequentialCtAbortFetch = (url, init) => new Promise((resolve, reject) => {
    startedAbortUrls.push(String(url));
    const signal = init?.signal;
    const abort = () => reject(new DOMException("The operation was aborted", "AbortError"));
    if (signal?.aborted) return abort();
    signal?.addEventListener("abort", abort, { once: true });
  });
  const ctAbortSub = createSubOperationTelemetry();
  const {
    value: ctAbortRaced,
    errors: ctAbortErrors,
  } = await withCapturedConsoleError(() =>
    raceAborted((controller) => runSslModule(FIXTURE_DOMAIN, {
      ctCache: createCertificateTransparencyCache({ fetcher: globalThis.fetch }),
      signal: controller.signal,
      accounting: { signal: controller.signal },
      subOps: ctAbortSub,
    }), sequentialCtAbortFetch));
  eq("CT-abort race returned the deadline fallback", ctAbortRaced?.outcome, "deadline_exceeded");
  const ctAbortBy = rowsByModule(ctAbortSub.snapshotRows());
  eq("crt.sh was the one CT provider started before cap",
    startedAbortUrls.filter((url) => url.includes("crt.sh")).length, 1);
  eq("bare HTTPS probe started concurrently with crt.sh",
    startedAbortUrls.filter((url) => url === `https://${FIXTURE_DOMAIN}`).length, 1);
  eq("CertSpotter fallback never started after external abort",
    startedAbortUrls.filter((url) => url.includes("certspotter")).length, 0);
  ok("only expected crt.sh AbortError was logged",
    ctAbortErrors.length === 1
      && ctAbortErrors[0].includes("[scan/ct/crt-sh]")
      && ctAbortErrors[0].includes("AbortError"),
    JSON.stringify(ctAbortErrors));
  eq("CT lookup in flight at cap attributed as aborted", ctAbortBy["ssl.ct_lookup"]?.outcome, "aborted");
  eq("bare probe in flight with CT attributed as aborted", ctAbortBy["ssl.https_probe_bare"]?.outcome, "aborted");
  ok("NO row for CT-abort post-cap www probe", !("ssl.https_probe_www" in ctAbortBy));
  ok("NO row for CT-abort post-cap redirect hop 1", !("ssl.http_redirect_hop_1" in ctAbortBy));
  ok("NO row for CT-abort post-cap redirect hop 2", !("ssl.http_redirect_hop_2" in ctAbortBy));
}

// ── 7. Persistence: ONE bounded D1 batch, never a per-row await loop ────────
// The rows land in the post-terminal chain ahead of snapshot Phase 8o, where the
// completed → report-ready gap is customer-facing. Sequential per-row writes
// there are a regression, so the single batch is a pinned contract.
{
  let batchCalls = 0;
  const binds = [];
  const db = {
    prepare: (sql) => {
      if (!/INSERT INTO scan_module_telemetry/i.test(sql)) throw new Error("unexpected SQL");
      return { bind: (...params) => { binds.push(params); return { params }; } };
    },
    batch: async (statements) => { batchCalls += 1; return statements.map(() => ({ success: true })); },
  };
  const sub = createSubOperationTelemetry(steppingClock());
  sub.finish(sub.begin("ssl", "https_probe_bare"), { outcome: "ok" });
  sub.begin("headers", "probe_get_https"); // left in flight → aborted
  await persistSubOperationTelemetry("scan_fixture_1", sub.snapshotRows(), { cybermeters_db: db });
  eq("exactly ONE batch call for all rows", batchCalls, 1);
  eq("both rows bound into the batch", binds.length, 2);
  eq("dotted module bound", binds[0][2], "ssl.https_probe_bare");
  eq("aborted outcome bound", binds[1][7], "aborted");
  ok("only existing columns bound (10 params)", binds.every((p) => p.length === 10));

  // Bounded even against an oversized snapshot handed in directly.
  batchCalls = 0; binds.length = 0;
  const oversized = Array.from({ length: SUB_OPERATION_TELEMETRY_ROW_LIMIT + 10 }, (_, i) => ({
    module: `ssl.op_${i}`, started_at: null, completed_at: null, duration_ms: 1, outbound_calls: null, outcome: "ok", timeout: false, error_class: null,
  }));
  await persistSubOperationTelemetry("scan_fixture_1", oversized, { cybermeters_db: db });
  eq("oversized row set stays bounded in one batch", binds.length, SUB_OPERATION_TELEMETRY_ROW_LIMIT);
  eq("still exactly one batch call", batchCalls, 1);

  const failingDb = {
    prepare: () => ({ bind: () => ({}) }),
    batch: async () => { throw new Error("D1 down"); },
  };
  let threw = false;
  try {
    await persistSubOperationTelemetry("scan_fixture_1", sub.snapshotRows(), { cybermeters_db: failingDb });
  } catch { threw = true; }
  eq("batch persistence stays non-fatal on DB failure", threw, false);
}

// ── 8. Engine wiring cannot be silently unwired ──────────────────────────────
{
  const engineSrc = fs.readFileSync(path.join(root, "workers", "scan-api", "src", "engines", "scan-engine.js"), "utf8");
  ok("engine creates the sub-op collector", /createSubOperationTelemetry\(now\)/.test(engineSrc));
  for (const mod of ["runSslModule", "runHeadersModule", "runSubdomainsModule"]) {
    ok(`engine passes subOps to ${mod}`, new RegExp(`${mod}\\(domain, \\{[^}]*subOps: subOpTelemetry`).test(engineSrc));
  }
  ok("engine persists sub-op rows through the batch helper",
    /await persistSubOperationTelemetry\(scanId, subOpTelemetry\.snapshotRows\(\), env\)/.test(engineSrc));
  // PIN: the single batch — not an insert per row. Without this pin someone
  // restores the per-row loop later and nobody notices until the customer-facing
  // report-ready gap widens again.
  const persistFn = engineSrc.slice(
    engineSrc.indexOf("export async function persistSubOperationTelemetry"),
    engineSrc.indexOf("// CT-R1: provider-attempt telemetry"),
  );
  ok("persistSubOperationTelemetry exists as its own helper", persistFn.length > 0);
  ok("sub-op persistence issues ONE batch()", /await env\.cybermeters_db\.batch\(statements\)/.test(persistFn));
  ok("sub-op persistence has NO per-row awaited run() loop", !/await[^\n]*\.run\(\)/.test(persistFn));
  ok("sub-op persistence is bounded by the row limit", /SUB_OPERATION_TELEMETRY_ROW_LIMIT/.test(persistFn));
}

if (pass + fail !== EXPECTED_ASSERTIONS) {
  console.log(`FAIL pinned assertion count — got ${pass + fail} want ${EXPECTED_ASSERTIONS}`);
  fail += 1;
}
console.log(`\nsubop-timing-telemetry: ${pass} passed, ${fail} failed`);
process.exit(fail > 0 ? 1 : 0);
