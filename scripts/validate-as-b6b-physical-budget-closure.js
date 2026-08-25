#!/usr/bin/env node
//
// AS-B6b physical subrequest closure oracle.
//
// This is intentionally a focused, standalone validator rather than a shared-gate
// pin. It proves the runtime law at the physical fetch boundary, the HTTPS -> HTTP
// fallback path, the full reserved worst-shape envelope, and the live scan-engine
// admin consumer that persists the resulting exposure evidence.

import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const engine = (file) => import(pathToFileURL(path.join(
  root, "workers", "scan-api", "src", "engines", file,
)).href);

const {
  CAPACITY_DEFAULTS,
  CRITICAL_PREFIXES_MANDATORY,
  PhysicalSubrequestCounter,
  dnsCacheKey,
  isSubrequestBudgetExhaustedError,
  makeDnsCache,
} = await engine("scan-budget.js");
const { makeReservedProbeFetch } = await engine("reserved-probe.js");
const { dnsQuery, dnsQueryGoogle, dnsQueryQuad9 } = await engine("dns.js");
const { createCertificateTransparencyCache } = await engine("ct-provider-cache.js");
const { probeAsset } = await engine("asset-intel.js");
const { runCriticalPrefixDiscovery, runReservedScan } = await engine("reserved-scan.js");
const { runScanEngine } = await engine("scan-engine.js");

let passed = 0;
let failed = 0;
function ok(id, condition, detail = "") {
  if (condition) {
    passed += 1;
    console.log(`PASS ${id}`);
  } else {
    failed += 1;
    console.log(`FAIL ${id}${detail ? ` — ${detail}` : ""}`);
  }
}
function eq(id, got, want) {
  ok(id, got === want, `got ${JSON.stringify(got)}, want ${JSON.stringify(want)}`);
}

const realFetch = globalThis.fetch;
const PUBLIC_A = "93.184.216.34";
const PUBLIC_AAAA = "2606:2800:220:1:248:1893:25c8:1946";
const html = (title = "Public Site", headers = {}) => new Response(
  `<html><title>${title}</title></html>`,
  { status: 200, headers: { "content-type": "text/html", ...headers } },
);
const dnsJson = (answers = []) => new Response(
  JSON.stringify({ Answer: answers }),
  { status: 200, headers: { "content-type": "application/dns-json" } },
);

function requestKind(value) {
  const url = String(value);
  if (/cloudflare-dns\.com\/dns-query|dns\.google\/resolve|dns\.quad9\.net\/dns-query/.test(url)) return "dns";
  if (/crt\.sh|api\.certspotter\.com/.test(url)) return "ct";
  if (/nvd\.nist\.gov|cisa\.gov|githubusercontent\.com/.test(url)) return "intelligence";
  return "http";
}

function dnsQuestion(value) {
  try {
    const url = new URL(String(value));
    return {
      name: (url.searchParams.get("name") || "").toLowerCase(),
      type: (url.searchParams.get("type") || "A").toUpperCase(),
    };
  } catch {
    return { name: "", type: "A" };
  }
}

// Cloudflare counts an automatically followed redirect as another physical
// subrequest even though JavaScript called fetch() only once. This focused
// single-hop stand-in reproduces that platform semantic: default/follow performs
// the second request, while redirect:"manual" exposes the 302 to product code.
function makeSingleHopRedirectFetcher(calls, finalResponse) {
  const target = "https://redirect-target.example.test/final";
  return async (value, init = {}) => {
    const url = String(value);
    calls.push({ url, redirect: init.redirect ?? "follow" });
    if (url === target) return finalResponse();
    const redirect = new Response("", { status: 302, headers: { location: target } });
    if ((init.redirect ?? "follow") === "manual") return redirect;
    calls.push({ url: target, redirect: "implicit-follow" });
    return finalResponse();
  };
}

function observingAccounting(counter, category) {
  const base = counter.contextFor(category);
  const errors = [];
  return {
    accounting: {
      ...base,
      recordError(error) {
        errors.push(error);
        base.recordError(error);
      },
    },
    errors,
  };
}

// RED-FIRST redirect law. The control proves this is not a passive mock that
// would hide the platform's automatic follow. The four production provider
// leaves must opt into manual redirect handling and fail closed on the 302.
{
  const controlCalls = [];
  const controlFetch = makeSingleHopRedirectFetcher(
    controlCalls,
    () => dnsJson([{ data: PUBLIC_A }]),
  );
  const control = await controlFetch("https://provider.example.test/start");
  ok(
    "ASB6B_REDIRECT_HARNESS_DEFAULT_FOLLOWS",
    control.status === 200
      && controlCalls.length === 2
      && controlCalls[1]?.redirect === "implicit-follow",
    JSON.stringify(controlCalls),
  );

  const cloudflareCounter = new PhysicalSubrequestCounter({ limit: 50, safetyMargin: 0 });
  const preexisting = cloudflareCounter.contextFor("preexisting");
  for (let i = 0; i < 49; i += 1) preexisting.recordAttempt();
  const cloudflareObservation = observingAccounting(cloudflareCounter, "dns-cloudflare");
  const cloudflareCalls = [];
  globalThis.fetch = makeSingleHopRedirectFetcher(
    cloudflareCalls,
    () => dnsJson([{ data: PUBLIC_A }]),
  );
  let cloudflareResult = null;
  let cloudflareError = null;
  try {
    cloudflareResult = await dnsQuery("example.com", "A", {
      accounting: cloudflareObservation.accounting,
    });
  } catch (error) {
    cloudflareError = error;
  } finally {
    globalThis.fetch = realFetch;
  }
  ok(
    "ASB6B_REDIRECT_AT_49_CHARGES_ONE_AND_FAILS_CLOSED",
    cloudflareResult == null
      && cloudflareCalls.length === 1
      && cloudflareCalls[0]?.redirect === "manual"
      && cloudflareCounter.issued === 50
      && cloudflareCounter.denied === 0
      && cloudflareError?.code === "redirect_refused"
      && cloudflareObservation.errors.length === 1
      && cloudflareObservation.errors[0]?.outcome === "redirect_refused",
    `calls=${JSON.stringify(cloudflareCalls)}, issued=${cloudflareCounter.issued}, denied=${cloudflareCounter.denied}, error=${cloudflareError?.code ?? null}`,
  );

  const resolverCases = [
    ["google", dnsQueryGoogle, "throws"],
    ["quad9", dnsQueryQuad9, "null"],
  ];
  const resolverObservations = [];
  for (const [provider, query, disposition] of resolverCases) {
    const counter = new PhysicalSubrequestCounter({ limit: 50, safetyMargin: 0 });
    const observation = observingAccounting(counter, `dns-${provider}`);
    const calls = [];
    globalThis.fetch = makeSingleHopRedirectFetcher(
      calls,
      () => dnsJson([{ data: PUBLIC_A }]),
    );
    let result = null;
    let error = null;
    try {
      result = await query("example.com", "A", { accounting: observation.accounting });
    } catch (caught) {
      error = caught;
    } finally {
      globalThis.fetch = realFetch;
    }
    resolverObservations.push({ provider, disposition, counter, calls, result, error, observation });
  }
  ok(
    "ASB6B_DNS_REDIRECTS_REFUSED_ALL_RESOLVERS",
    resolverObservations.every(({ disposition, counter, calls, result, error, observation }) =>
      calls.length === 1
      && calls[0]?.redirect === "manual"
      && counter.issued === 1
      && counter.denied === 0
      && observation.errors.length === 1
      && observation.errors[0]?.outcome === "redirect_refused"
      && (disposition === "throws" ? error?.code === "redirect_refused" : result == null)),
    JSON.stringify(resolverObservations.map(({ provider, counter, calls, result, error, observation }) => ({
      provider,
      issued: counter.issued,
      denied: counter.denied,
      calls,
      result,
      error: error?.code ?? null,
      observed: observation.errors.map((item) => item?.outcome ?? null),
    }))),
  );

  const criticalCounter = new PhysicalSubrequestCounter({ limit: 50, safetyMargin: 0 });
  const criticalCalls = [];
  globalThis.fetch = makeSingleHopRedirectFetcher(
    criticalCalls,
    () => dnsJson([{ data: PUBLIC_A }]),
  );
  let criticalResult;
  try {
    criticalResult = await runCriticalPrefixDiscovery(
      "example.com",
      makeDnsCache(),
      ["admin"],
      { accounting: criticalCounter.contextFor("critical-prefix-redirect") },
    );
  } finally {
    globalThis.fetch = realFetch;
  }
  ok(
    "ASB6B_CRITICAL_PREFIX_REDIRECT_NOT_CHECKED_CLEAN",
    criticalCalls.length === 1
      && criticalResult?.checked === 0
      && criticalResult?.requested === 1
      && criticalResult?.found === 0
      && criticalResult?.incomplete === true
      && criticalResult?.incomplete_reason === "redirect_refused"
      && criticalResult?.deferred_count === 1,
    JSON.stringify({ calls: criticalCalls, result: criticalResult }),
  );

  let ordinaryFailureCalls = 0;
  globalThis.fetch = async () => {
    ordinaryFailureCalls += 1;
    throw new TypeError("provider offline");
  };
  let ordinaryFailureResult;
  try {
    ordinaryFailureResult = await runCriticalPrefixDiscovery(
      "example.com",
      makeDnsCache(),
      ["admin"],
      { accounting: new PhysicalSubrequestCounter({ limit: 50, safetyMargin: 0 }).contextFor("critical-prefix-offline") },
    );
  } finally {
    globalThis.fetch = realFetch;
  }
  ok(
    "ASB6B_CRITICAL_PREFIX_ORDINARY_FAILURE_SEMANTICS_UNCHANGED",
    ordinaryFailureCalls === 1
      && ordinaryFailureResult?.checked === 1
      && ordinaryFailureResult?.requested === 1
      && ordinaryFailureResult?.found === 0
      && ordinaryFailureResult?.incomplete !== true,
    JSON.stringify({ calls: ordinaryFailureCalls, result: ordinaryFailureResult }),
  );

  const ctCounter = new PhysicalSubrequestCounter({ limit: 50, safetyMargin: 0 });
  const ctObservation = observingAccounting(ctCounter, "ct-crt-sh");
  const ctCalls = [];
  const ctCache = createCertificateTransparencyCache({
    accounting: ctObservation.accounting,
    fetcher: makeSingleHopRedirectFetcher(
      ctCalls,
      () => new Response("[]", { status: 200, headers: { "content-type": "application/json" } }),
    ),
    policies: {
      crt_sh: { timeoutMs: 1_000, maxAttempts: 2, backoffMs: 0 },
      certspotter: { timeoutMs: 1_000, maxAttempts: 2, backoffMs: 0 },
    },
    timeoutSignal: () => undefined,
    sleep: async () => {},
  });
  const ctResult = await ctCache.get("example.com", "crt_sh", {
    accounting: ctObservation.accounting,
    module: "subdomains",
  });
  const ctRows = ctCache.telemetrySnapshot({
    modules: {
      subdomains: {
        incomplete: true,
        incomplete_reason: "ct_sources_unavailable",
        sources: { crt_sh: { error: "redirect_refused" } },
      },
    },
    scanQuality: { status: "partial" },
  });
  const ctHealth = ctCache.healthSnapshot().crt_sh;
  ok(
    "ASB6B_CT_REDIRECT_REFUSED_UNAVAILABLE",
    ctCalls.length === 1
      && ctCalls[0]?.redirect === "manual"
      && ctCounter.issued === 1
      && ctCounter.denied === 0
      && ctResult?.status === "unavailable"
      && ctResult?.error === "redirect_refused"
      && ctResult?.physical_attempt_state === "terminal_failure"
      && ctHealth?.outcome === "unavailable"
      && ctHealth?.attempts === 1
      && ctHealth?.final_error === "redirect_refused"
      && ctRows.length === 1
      && ctRows[0]?.redirect_disposition === "redirect_refused"
      && !/timeout|budget/i.test(JSON.stringify({ result: ctResult, health: ctHealth, rows: ctRows })),
    JSON.stringify({ calls: ctCalls, issued: ctCounter.issued, denied: ctCounter.denied, result: ctResult, health: ctHealth, rows: ctRows }),
  );
}

// 1) The hard boundary is inclusive: physical attempts 1..50 issue; candidate 51
// is refused before global fetch. The admission ledger remains separately capped
// at 45 so the two concepts cannot silently collapse into one counter.
{
  const counter = new PhysicalSubrequestCounter({ limit: 50, safetyMargin: 5 });
  const accounting = counter.contextFor("boundary");
  let physical = 0;
  let refusal = null;
  globalThis.fetch = async () => {
    physical += 1;
    return new Response("ok", { status: 200 });
  };
  try {
    for (let candidate = 1; candidate <= 51; candidate += 1) {
      try {
        accounting.assertCanIssue();
        accounting.recordAttempt();
        await fetch(`https://boundary-${candidate}.example.test/`);
      } catch (error) {
        refusal = { candidate, error };
        break;
      }
    }
  } finally {
    globalThis.fetch = realFetch;
  }

  ok(
    "ASB6B_COUNTER_RECONCILES_PHYSICAL",
    counter.issued === physical,
    `counter=${counter.issued}, physical=${physical}`,
  );
  ok(
    "ASB6B_BOUNDARY_50_ISSUED_51_DENIED",
    counter.issued === 50
      && physical === 50
      && refusal?.candidate === 51
      && isSubrequestBudgetExhaustedError(refusal?.error)
      && counter.denied === 1,
    `issued=${counter.issued}, physical=${physical}, candidate=${refusal?.candidate ?? null}, denied=${counter.denied}`,
  );
  eq("ASB6B_ADMISSION_LIMIT_REMAINS_45", counter.snapshot().admission_limit, 45);
}

// 2) A failed HTTPS GET followed by a successful HTTP fallback is two physical
// attempts and two internal charges. A preseeded DNS cache isolates this assertion
// to the protocol fallback itself.
{
  const host = "fallback.example.com";
  const cache = makeDnsCache();
  cache.set(dnsCacheKey(host, "A"), { Answer: [{ data: PUBLIC_A }] });
  cache.set(dnsCacheKey(host, "AAAA"), { Answer: [{ data: PUBLIC_AAAA }] });
  const counter = new PhysicalSubrequestCounter({ limit: 50, safetyMargin: 5 });
  const accounting = counter.contextFor("fallback");
  const fetcher = makeReservedProbeFetch({ cache, accounting });
  const calls = [];
  globalThis.fetch = async (value) => {
    const url = String(value);
    calls.push(url);
    if (url === `https://${host}`) throw new TypeError("connection reset");
    if (url === `http://${host}`) return html("Fallback reached");
    throw new Error(`unexpected fallback request: ${url}`);
  };
  let asset;
  try {
    asset = await probeAsset(host, { fetcher });
  } finally {
    globalThis.fetch = realFetch;
  }

  ok(
    "ASB6B_FALLBACK_INTERNAL_EQUALS_PHYSICAL",
    calls.length === 2
      && counter.issued === 2
      && calls[0] === `https://${host}`
      && calls[1] === `http://${host}`,
    `calls=${JSON.stringify(calls)}, issued=${counter.issued}`,
  );
  ok("ASB6B_FALLBACK_RESULT_REACHABLE", asset?.reachable === true && asset?.url === `http://${host}`);
}

function nextRedirect(url) {
  const parsed = new URL(url);
  const match = parsed.hostname.match(/^(s|f)([123])-(.+)\.redirect\.test$/);
  if (!match) {
    const lane = parsed.protocol === "https:" ? "s" : "f";
    const encoded = parsed.hostname.replace(/[^a-z0-9-]/gi, "-");
    return `${parsed.protocol}//${lane}1-${encoded}.redirect.test/`;
  }
  const [, lane, rawHop, encoded] = match;
  const hop = Number(rawHop);
  if (hop < 3) return `${parsed.protocol}//${lane}${hop + 1}-${encoded}.redirect.test/`;
  return null;
}

// 3) Full worst-shape reserved execution. Every mandatory host resolves. HTTPS
// walks three cross-host redirects and then fails; HTTP walks three redirects.
// The theoretical envelope is >200 calls, but the physical guard must terminate
// it at exactly 50 and retain explicit incomplete/not-assessed evidence.
{
  const physicalCalls = [];
  globalThis.fetch = async (value) => {
    const url = String(value);
    physicalCalls.push(url);
    const kind = requestKind(url);
    if (kind === "dns") {
      const { type } = dnsQuestion(url);
      if (type === "A") return dnsJson([{ data: PUBLIC_A }]);
      if (type === "AAAA") return dnsJson([{ data: PUBLIC_AAAA }]);
      return dnsJson([]);
    }
    if (kind === "ct") return new Response("[]", { status: 200, headers: { "content-type": "application/json" } });
    if (kind === "http") {
      const parsed = new URL(url);
      const redirect = nextRedirect(url);
      if (/^s3-/.test(parsed.hostname)) throw new TypeError("https terminal reset");
      if (/^f3-/.test(parsed.hostname)) return html("HTTP terminal");
      return new Response("", { status: 302, headers: { location: redirect } });
    }
    return new Response("{}", { status: 200, headers: { "content-type": "application/json" } });
  };

  let result;
  let thrown = null;
  try {
    result = await runReservedScan("example.com", {
      capacity: { ...CAPACITY_DEFAULTS, mode: "reserved" },
    });
  } catch (error) {
    thrown = error;
  } finally {
    globalThis.fetch = realFetch;
  }

  const physical = result?.physicalBudget || {};
  const modules = result?.modules || {};
  const exposure = modules.asset_exposure || {};
  const critical = modules.critical_prefix_discovery || {};
  const categories = Object.values(physical.by_category || {}).reduce((sum, count) => sum + count, 0);
  const skipped = Object.entries(modules).filter(([, value]) => value?.skipped === true);
  const notAssessed = (exposure.assets || []).filter((asset) =>
    asset?.reachable == null || ["not_executed", "deferred_capacity", "timed_out"].includes(asset?.probe_status));

  ok("ASB6B_WORST_SHAPE_COMPLETES_WITHOUT_THROW", thrown == null, String(thrown?.stack || thrown || ""));
  ok(
    "ASB6B_WORST_SHAPE_HARD_CAP_50",
    physicalCalls.length === 50 && physical.issued === 50 && physical.denied > 0,
    `physical=${physicalCalls.length}, issued=${physical.issued}, denied=${physical.denied}`,
  );
  ok(
    "ASB6B_WORST_SHAPE_COUNTER_RECONCILES",
    physicalCalls.length === physical.issued && categories === physical.issued,
    `physical=${physicalCalls.length}, issued=${physical.issued}, categories=${categories}`,
  );
  ok(
    "ASB6B_CRITICAL_PREFIX_ENVELOPE_PRESERVED",
    critical.checked === CRITICAL_PREFIXES_MANDATORY.length
      && critical.found === CRITICAL_PREFIXES_MANDATORY.length
      && critical.items?.includes("admin.example.com"),
    JSON.stringify(critical),
  );
  ok(
    "ASB6B_EXHAUSTION_IS_HONESTLY_INCOMPLETE",
    exposure.incomplete === true
      && exposure.incomplete_reason === "subrequest_budget_exhausted"
      && notAssessed.length > 0,
    `incomplete=${exposure.incomplete}, reason=${exposure.incomplete_reason}, not_assessed=${notAssessed.length}`,
  );
  ok(
    "ASB6B_POST_EXPOSURE_MODULES_NOT_FAKE_CLEAN",
    skipped.length > 0 && skipped.every(([, value]) => value.skip_reason === "subrequest_budget"),
    JSON.stringify(skipped.map(([name, value]) => [name, value.skip_reason])),
  );
}

function makeWorkerEnv(onReport) {
  const statement = {
    bind() { return this; },
    async run() { return {}; },
    async all() { return { results: [] }; },
    async first() { return null; },
  };
  return {
    cybermeters_db: {
      prepare: () => statement,
      async batch() { return []; },
    },
    cybermeters_reports: {
      async put(_key, body) {
        try { onReport(JSON.parse(body)); } catch { /* validator records null */ }
        return {};
      },
      async get() { return null; },
      async delete() { return {}; },
    },
    SCAN_CAPACITY_MODE: "reserved",
  };
}

// 4) The actual scan engine must consume the reserved exposure evidence before
// scoring/persistence. This also reconciles every mocked network call across the
// reserved scan and the later intelligence stages against the final physical meter.
{
  const physicalCalls = [];
  let report = null;
  globalThis.fetch = async (value) => {
    const url = String(value);
    physicalCalls.push(url);
    const kind = requestKind(url);
    if (kind === "dns") {
      const { type } = dnsQuestion(url);
      if (type === "A") return dnsJson([{ data: PUBLIC_A }]);
      if (type === "AAAA") return dnsJson([{ data: PUBLIC_AAAA }]);
      return dnsJson([]);
    }
    if (kind === "ct") return new Response("[]", { status: 200, headers: { "content-type": "application/json" } });
    if (kind === "http") {
      const hostname = new URL(url).hostname;
      return hostname === "admin.example.com"
        ? html("Jenkins", { server: "Jetty" })
        : html("Public Site");
    }
    return new Response("{}", { status: 200, headers: { "content-type": "application/json" } });
  };

  let engineError = null;
  try {
    await runScanEngine(
      "scan_asb6b",
      "domain_asb6b",
      "workspace_asb6b",
      "example.com",
      makeWorkerEnv((value) => { report = value; }),
    );
  } catch (error) {
    engineError = error;
  } finally {
    globalThis.fetch = realFetch;
  }

  const modules = report?.modules || {};
  const admin = modules.admin_surface_detection || {};
  const physical = modules.scan_budget?.physical || {};
  const findings = Array.isArray(report?.findings) ? report.findings : [];
  ok("ASB6B_LIVE_ENGINE_COMPLETES", engineError == null && report != null, String(engineError?.stack || engineError || ""));
  ok(
    "ASB6B_LIVE_ADMIN_CONSUMER_PERSISTS",
    admin.evidence_status === "issue_detected"
      && admin.services?.some((service) => service.product === "Jenkins" && service.hostname === "admin.example.com")
      && findings.some((finding) => finding.id === "admin_surface_critical"),
    `admin=${JSON.stringify(admin)}, finding_ids=${JSON.stringify(findings.map((finding) => finding.id))}`,
  );
  ok(
    "ASB6B_LIVE_ENGINE_COUNTER_RECONCILES",
    physical.issued === physicalCalls.length && physical.issued <= 50 && physical.denied >= 0,
    `issued=${physical.issued}, physical=${physicalCalls.length}, denied=${physical.denied}`,
  );
  ok(
    "ASB6B_LIVE_ENGINE_CRITICAL_HOST_PROBED",
    modules.asset_exposure?.assets?.some((asset) => asset.host === "admin.example.com" && asset.reachable === true),
  );
}

// The approved SSRF-safe primitive is a fixed input to this work order. Mutation
// subprocesses explicitly skip this check because they operate only on an isolated
// temporary copy; the candidate worktree is always verified here in normal mode.
if (process.env.ASB6B_MUTANT_MODE !== "1") {
  const reservedProbePath = path.join(root, "workers", "scan-api", "src", "engines", "reserved-probe.js");
  const digest = crypto.createHash("sha256").update(fs.readFileSync(reservedProbePath)).digest("hex");
  eq(
    "ASB6B_RESERVED_PROBE_IMMUTABLE_HASH",
    digest,
    "97b79ec1b43ea688060806af087a292ba414cacc188878a37ad369409b5b0e1e",
  );
}

console.log(`AS-B6b physical-budget closure: ${passed} passed, ${failed} failed`);
if (failed > 0) process.exit(1);
