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
const { probeAsset } = await engine("asset-intel.js");
const { runReservedScan } = await engine("reserved-scan.js");
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
