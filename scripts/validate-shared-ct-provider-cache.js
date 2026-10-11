#!/usr/bin/env node
//
// Item 5 / PR-5.2: SSL and subdomain discovery must share one parsed CT provider
// result per scan. Provider failure is an explicit unavailable result, never an
// available empty array. Includes executable sharing and false-empty mutations.
// CertSpotter is the only CT provider: its failure is a total CT loss.
// CI-blocking. Requires Node 24+.
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const scriptPath = fileURLToPath(import.meta.url);
const root = path.join(path.dirname(scriptPath), "..");
const engine = (file) => pathToFileURL(
  path.join(root, "workers", "scan-api", "src", "engines", file)
).href;

const breakSharing = process.argv.includes("--mutate-break-sharing");
const falseEmpty = process.argv.includes("--mutate-failure-to-empty");
const reservedDistinctCaches = process.argv.includes("--mutate-reserved-distinct-caches");

const RESERVED_DISTINCT_CACHE_MUTANT = Object.freeze({
  id: "CTCACHE-M3-reserved-distinct-caches",
  before: "      ctCache: sharedCtCache,\n      signal: consumerSignal,",
  after: "      ctCache: createCertificateTransparencyCache(),\n      signal: consumerSignal,",
});

function replaceExactlyOnce(source, before, after, id) {
  const matches = source.split(before).length - 1;
  if (matches !== 1) throw new Error(`${id}: anchor count ${matches}, expected 1`);
  return source.replace(before, after);
}

const { createCertificateTransparencyCache } = await import(engine("ct-provider-cache.js"));
const { runSslModule } = await import(engine("ssl-scan.js"));
const { runSubdomainsModule } = await import(engine("subdomains-scan.js"));
const { subdomainDiscoveryComplete } = await import(engine("asset-inventory.js"));
const { runCertificateIntelligenceModule } = await import(engine("cert-intel.js"));

let pass = 0;
let fail = 0;
const ok = (name, condition, detail = "") => {
  condition ? pass++ : fail++;
  if (!condition) console.log(`FAIL ${name}${detail ? ` — ${detail}` : ""}`);
};
const eq = (name, got, want) =>
  ok(name, got === want, `got ${JSON.stringify(got)} want ${JSON.stringify(want)}`);
const same = (name, got, want) =>
  eq(name, JSON.stringify(got), JSON.stringify(want));

const realFetch = globalThis.fetch;
const realNow = Date.now;
const realRandom = Math.random;
const realConsoleError = console.error;
const NOW = "2026-07-23T12:00:00.000Z";

Date.now = () => Date.parse(NOW);
Math.random = () => 0.123456789;
console.error = () => {};

const jsonResponse = (body, status = 200) => new Response(JSON.stringify(body), {
  status,
  headers: { "content-type": "application/json" },
});

// CT provider calls are injected through the cache; remaining global fetches are
// deterministic HTTPS/HTTP and wildcard-DoH probes used by the real modules.
globalThis.fetch = async (url) => {
  if (String(url).includes("/dns-query?")) {
    return jsonResponse({ Status: 0, Answer: [] });
  }
  return new Response("", { status: 200 });
};

// CertSpotter issuances. SSL must select the longest-lived unexpired issuance
// that covers the root domain (not the longer-lived subdomain-only one), and
// measure its shared SANs from its own DNS names; subdomain discovery merges
// every issuance's in-scope names.
const certSpotterBody = [
  {
    not_after: "2026-10-01T12:00:00.000Z",
    not_before: "2026-06-01T12:00:00.000Z",
    issuer: { name: "Example Root CA" },
    dns_names: ["example.com", "www.example.com", "api.example.com", "shared.example.net"],
  },
  {
    not_after: "2026-08-01T12:00:00.000Z",
    not_before: "2026-05-01T12:00:00.000Z",
    issuer: { name: "Older CA" },
    dns_names: ["example.com"],
  },
  {
    not_after: "2026-09-01T12:00:00.000Z",
    not_before: "2026-06-15T12:00:00.000Z",
    issuer: { name: "Spot CA" },
    dns_names: ["example.com", "app.example.com", "admin.example.com"],
  },
  {
    not_after: "2027-01-01T12:00:00.000Z",
    not_before: "2026-07-01T12:00:00.000Z",
    issuer: { name: "Subdomain-only CA" },
    dns_names: ["api.example.com"],
  },
];

function providerFetcher({ certspotter = certSpotterBody, calls, urls = [] }) {
  return async (url) => {
    const value = String(url);
    urls.push(value);
    if (value.startsWith("https://api.certspotter.com/")) {
      calls.certspotter++;
      if (certspotter instanceof Error) throw certspotter;
      return jsonResponse(certspotter);
    }
    throw new Error(`unexpected provider URL: ${value}`);
  };
}

function cacheFor(fetcher) {
  const cache = createCertificateTransparencyCache({ fetcher });
  if (!falseEmpty) return cache;
  return {
    async get(domain, provider, opts) {
      const result = await cache.get(domain, provider, opts);
      return result.status === "unavailable"
        ? { ...result, status: "available", data: [], error: null }
        : result;
    },
  };
}

function certificateFields(ssl) {
  const names = [
    "cert_expiry_days", "cert_age_days", "cert_not_before", "cert_not_after",
    "cert_issuer", "cert_subject", "cert_san_count", "cert_raw_san_count",
    "cert_wildcard_san_count", "cert_shared_san_count", "cert_san_names",
  ];
  return Object.fromEntries(names.map((name) => [name, ssl[name]]));
}

async function runPair(fetcher, { shared = true } = {}) {
  const sharedCache = cacheFor(fetcher);
  const sslCache = sharedCache;
  const subdomainsCache = shared && !breakSharing ? sharedCache : cacheFor(fetcher);
  const [ssl, subdomains] = await Promise.all([
    runSslModule("example.com", { ctCache: sslCache }),
    runSubdomainsModule("example.com", { ctCache: subdomainsCache }),
  ]);
  return { ssl, subdomains };
}

try {
  // ── Production wiring: one cache instance reaches both consumers ──────────
  {
    const scanEngineSource = fs.readFileSync(
      path.join(root, "workers", "scan-api", "src", "engines", "scan-engine.js"),
      "utf8"
    );
    let reservedSource = fs.readFileSync(
      path.join(root, "workers", "scan-api", "src", "engines", "reserved-scan.js"),
      "utf8"
    );
    if (reservedDistinctCaches) {
      reservedSource = replaceExactlyOnce(
        reservedSource,
        RESERVED_DISTINCT_CACHE_MUTANT.before,
        RESERVED_DISTINCT_CACHE_MUTANT.after,
        RESERVED_DISTINCT_CACHE_MUTANT.id,
      );
    }
    eq("scan engine creates one per-scan CT cache",
      (scanEngineSource.match(/const ctCache = createCertificateTransparencyCache\(/g) || []).length,
      1);
    ok("default scan passes that cache to SSL and subdomains",
      /runSslModule\(domain, \{ dnsResolver: dnsQuery, dnsCache, accounting, signal, ctCache, subOps: subOpTelemetry, now: \(\) => certificateNowMs \}\)/.test(scanEngineSource) &&
        /runSubdomainsModule\(domain, \{ accounting, signal, cache: dnsCache, ctCache, subOps: subOpTelemetry, globalDeadlineProvenance: \(\) => deadline\.globalDeadlineProvenance\(\) \}\)/.test(scanEngineSource));
    ok("reserved scan reuses one cache for SSL and subdomains",
      /runReservedScan\(domain, \{\s*capacity,\s*ctCache,\s*dnsCache,\s*knownAssetHosts,\s*signal: deadline\.signal,\s*globalDeadlineProvenance: \(\) => deadline\.globalDeadlineProvenance\(\),/.test(scanEngineSource) &&
        /runSslModule\(domain, \{\s*dnsResolver: dnsQuery, dnsCache, (?:accounting,\s*)?ctCache: sharedCtCache,\s*signal: consumerSignal\s*\}\)/.test(reservedSource) &&
        /run: \(consumerSignal\) => runSubdomainsModule\(domain, \{\s*(?:accounting,\s*)?cache: dnsCache,\s*ctCache: sharedCtCache,\s*signal: consumerSignal,\s*globalSignal: signal,\s*globalDeadlineProvenance,\s*\}\)/.test(reservedSource));
  }

  // ── Successful provider results: one lookup and byte-stable consumers ─────
  const sharedCalls = { certspotter: 0 };
  const sharedUrls = [];
  const shared = await runPair(providerFetcher({ calls: sharedCalls, urls: sharedUrls }));

  eq("shared scan performs one CertSpotter fetch", sharedCalls.certspotter, 1);
  eq("shared scan contacts no other CT source", sharedUrls.length, 1);
  eq("shared CertSpotter request is domain-wide for both consumers",
    new URL(sharedUrls[0]).searchParams.get("domain"), "example.com");
  ok("shared CertSpotter request includes subdomains, DNS names and issuer data",
    /include_subdomains=true/.test(sharedUrls[0]) &&
      /expand=dns_names/.test(sharedUrls[0]) &&
      /expand=issuer/.test(sharedUrls[0]));
  eq("SSL selects the longest-lived root-covering certificate", shared.ssl.cert_not_after, certSpotterBody[0].not_after);
  eq("SSL preserves the issuer", shared.ssl.cert_issuer, "Example Root CA");
  eq("SSL claims no certificate subject from CertSpotter", shared.ssl.cert_subject, null);
  same("SSL preserves normalized SANs", shared.ssl.cert_san_names,
    ["example.com", "www.example.com", "api.example.com"]);
  eq("SSL preserves raw SAN count", shared.ssl.cert_raw_san_count, 4);
  eq("SSL preserves wildcard SAN count", shared.ssl.cert_wildcard_san_count, 0);
  eq("SSL measures shared SANs from the issuance DNS names", shared.ssl.cert_shared_san_count, 1);
  same("SSL records exactly the CertSpotter source", shared.ssl.ct_sources,
    { certspotter: { count: 4, error: null } });
  eq("subdomains preserve merged count", shared.subdomains.count, 5);
  same("subdomains preserve sorted merged names", shared.subdomains.items,
    ["admin.example.com", "api.example.com", "app.example.com", "example.com", "www.example.com"]);
  // app/api are everyday production names and are never classified sensitive.
  same("subdomains preserve sensitive classification", shared.subdomains.sensitive,
    ["admin.example.com"]);
  same("subdomains preserve per-source success shape", shared.subdomains.sources, {
    certspotter: { count: 5, error: null },
  });
  same("subdomains declare exactly the CertSpotter provider", shared.subdomains.ct_providers, ["certspotter"]);
  ok("CertSpotter success leaves subdomain discovery complete",
    shared.subdomains.incomplete !== true && !shared.subdomains.ct_error &&
      subdomainDiscoveryComplete({
        subdomains: shared.subdomains,
        dns_bruteforce: { items: [], error: null },
      }) === true);

  const separateCalls = { certspotter: 0 };
  const separate = await runPair(providerFetcher({ calls: separateCalls }), { shared: false });
  same("certificate fields are byte-identical to separate pre-cache consumption",
    certificateFields(shared.ssl), certificateFields(separate.ssl));
  same("subdomain result is byte-identical to separate pre-cache consumption",
    shared.subdomains, separate.subdomains);
  eq("separate pre-cache consumption demonstrates duplicate CertSpotter calls",
    separateCalls.certspotter, 2);

  // ── Cache key and in-flight promise contract ──────────────────────────────
  {
    const calls = { certspotter: 0 };
    const cache = cacheFor(providerFetcher({ calls }));
    const first = cache.get("Example.COM.", "certspotter");
    const second = cache.get("example.com", "certspotter");
    ok("same normalized provider key reuses the in-flight promise", first === second);
    const [a, b] = await Promise.all([first, second]);
    ok("shared callers receive the same cached result object", a === b);
    eq("normalized key performs one provider fetch", calls.certspotter, 1);
    eq("available provider status is explicit", a.status, "available");
    ok("available provider returns an array", Array.isArray(a.data));
    eq("available provider has no error", a.error, null);
  }

  // The cache declares its provider set; a provider it does not declare is
  // refused explicitly and never reaches the network.
  {
    const calls = { certspotter: 0 };
    const urls = [];
    const cache = createCertificateTransparencyCache({ fetcher: providerFetcher({ calls, urls }) });
    same("cache declares exactly the CertSpotter provider", cache.providers, ["certspotter"]);
    const undeclared = await cache.get("example.com", "provider_b");
    eq("undeclared provider is explicit unavailable", undeclared.status, "unavailable");
    eq("undeclared provider never returns false-empty data", undeclared.data, null);
    eq("undeclared provider carries a safe reason", undeclared.error, "unsupported provider");
    eq("undeclared provider issues no outbound request", urls.length, 0);
  }

  {
    let fetchCalls = 0;
    const cache = cacheFor(async () => {
      fetchCalls++;
      throw new DOMException("provider timed out", "TimeoutError");
    });
    const timedOut = await cache.get("example.com", "certspotter");
    eq("provider timeout is explicit unavailable", timedOut.status, "unavailable");
    eq("provider timeout never returns false-empty data", timedOut.data, null);
    eq("provider timeout retains a safe error", timedOut.error, "fetch failed");
    eq("provider timeout is cached after one bounded retry", fetchCalls, 2);
  }

  {
    let fetchCalls = 0;
    const cache = cacheFor(async () => {
      fetchCalls++;
      return jsonResponse([]);
    });
    const blocked = await cache.get("example.com", "certspotter", {
      accounting: {
        assertCanIssue() { throw new DOMException("module budget exhausted", "AbortError"); },
      },
    });
    eq("pre-fetch cancellation becomes explicit unavailable", blocked.status, "unavailable");
    eq("pre-fetch cancellation never returns false-empty data", blocked.data, null);
    eq("pre-fetch cancellation issues no outbound request", fetchCalls, 0);
  }

  // ── CertSpotter unavailable: total CT loss, never healthy ─────────────────
  // With one CT provider there is no fallback: its failure leaves both
  // consumers without CT evidence, and that must read as incomplete/unknown.
  // (The former two-provider fallback section has no remaining meaning and was
  // removed.)
  const blackoutCalls = { certspotter: 0 };
  const blackout = await runPair(providerFetcher({
    calls: blackoutCalls,
    certspotter: new Error("CertSpotter down"),
  }));
  eq("blackout bounds shared CertSpotter attempts", blackoutCalls.certspotter, 2);
  eq("blackout leaves SSL certificate unknown", blackout.ssl.cert_not_after, null);
  eq("blackout leaves SSL issuer unknown", blackout.ssl.cert_issuer, null);
  same("blackout exposes SSL CertSpotter failure", blackout.ssl.ct_sources,
    { certspotter: { count: 0, error: "fetch failed" } });
  same("blackout exposes subdomain CertSpotter failure", blackout.subdomains.sources,
    { certspotter: { count: 0, error: "fetch failed" } });
  eq("blackout carries the CT diagnostic", blackout.subdomains.ct_error,
    "CT source failed — certspotter: fetch failed");
  ok("blackout marks subdomain discovery incomplete",
    blackout.subdomains.incomplete === true &&
      blackout.subdomains.incomplete_reason === "ct_sources_unavailable" &&
      blackout.subdomains.count === 0);
  ok("blackout is not disappearance-complete",
    subdomainDiscoveryComplete({
      subdomains: blackout.subdomains,
      dns_bruteforce: { items: [], error: null },
    }) === false);
  const intelligence = runCertificateIntelligenceModule({
    ssl: blackout.ssl,
    subdomains: blackout.subdomains,
    dns_bruteforce: { items: [] },
  }, "example.com");
  eq("blackout remains unknown rather than healthy", intelligence.certificate_risk_level, "unknown");
  eq("blackout retains the existing incomplete reason", intelligence.incomplete_reason, "ct_sources_unavailable");

  // ── Successful empty is distinct from provider unavailable ────────────────
  const emptyCalls = { certspotter: 0 };
  const empty = await runPair(providerFetcher({
    calls: emptyCalls,
    certspotter: [],
  }));
  eq("successful-empty CertSpotter has no SSL provider error", empty.ssl.ct_sources.certspotter?.error, null);
  eq("successful-empty CertSpotter has no subdomain provider error", empty.subdomains.sources.certspotter.error, null);
  ok("successful-empty result does not claim a provider blackout", !empty.subdomains.ct_error);
  ok("successful-empty result is measured, not incomplete",
    empty.subdomains.incomplete !== true &&
      subdomainDiscoveryComplete({
        subdomains: empty.subdomains,
        dns_bruteforce: { items: [], error: null },
      }) === true);
  eq("successful-empty still performs one CertSpotter fetch", emptyCalls.certspotter, 1);

  // Execute all three defect-class mutations. Each nested validator must turn red.
  if (!breakSharing && !falseEmpty && !reservedDistinctCaches) {
    const sharingMutation = spawnSync(process.execPath, [scriptPath, "--mutate-break-sharing"], {
      cwd: root,
      encoding: "utf8",
    });
    ok("mutation: breaking cache sharing makes the validator RED",
      sharingMutation.status !== 0 &&
        sharingMutation.stdout.includes("FAIL shared scan performs one CertSpotter fetch"));

    const failureMutation = spawnSync(process.execPath, [scriptPath, "--mutate-failure-to-empty"], {
      cwd: root,
      encoding: "utf8",
    });
    ok("mutation: converting unavailable to empty-as-healthy makes the validator RED",
      failureMutation.status !== 0 &&
        failureMutation.stdout.includes("FAIL provider timeout is explicit unavailable"));

    const reservedDistinctMutation = spawnSync(
      process.execPath,
      [scriptPath, "--mutate-reserved-distinct-caches"],
      { cwd: root, encoding: "utf8" },
    );
    const reservedDistinctOutput =
      `${reservedDistinctMutation.stdout || ""}\n${reservedDistinctMutation.stderr || ""}`;
    const reservedDistinctKilled =
      reservedDistinctMutation.status === 1 &&
      reservedDistinctMutation.signal === null &&
      reservedDistinctMutation.stdout.includes(
        "FAIL reserved scan reuses one cache for SSL and subdomains",
      ) &&
      reservedDistinctMutation.stdout.includes(
        // 57 assertions run in a nested (mutation) process: the three mutation
        // checks below only run in the parent. CertSpotter-only CT removed the
        // two-provider fallback section and added provider-set/blackout checks.
        "shared-ct-provider-cache: 56 passed, 1 failed",
      ) &&
      !/SyntaxError|ERR_MODULE_NOT_FOUND|uncaught exception/i.test(reservedDistinctOutput);
    ok(
      `mutation: ${RESERVED_DISTINCT_CACHE_MUTANT.id} is killed by the named reserved-sharing assertion`,
      reservedDistinctKilled,
    );
    if (reservedDistinctKilled) {
      console.log(
        `KILLED ${RESERVED_DISTINCT_CACHE_MUTANT.id} — FAIL reserved scan reuses one cache for SSL and subdomains`,
      );
    }
  }
} finally {
  globalThis.fetch = realFetch;
  Date.now = realNow;
  Math.random = realRandom;
  console.error = realConsoleError;
}

console.log(`\nshared-ct-provider-cache: ${pass} passed, ${fail} failed`);
if (fail) {
  console.error("shared-ct-provider-cache validation FAILED");
  process.exit(1);
}
console.log("shared-ct-provider-cache validation passed");
process.exit(0);
