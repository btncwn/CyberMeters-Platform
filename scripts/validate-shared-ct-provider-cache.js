#!/usr/bin/env node
//
// Item 5 / PR-5.2: SSL and subdomain discovery must share one parsed CT provider
// result per scan. Provider failure is an explicit unavailable result, never an
// available empty array. Includes executable sharing and false-empty mutations.
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

const crtBody = [
  {
    not_after: "2026-10-01T12:00:00.000Z",
    not_before: "2026-06-01T12:00:00.000Z",
    issuer_name: "Example Root CA",
    common_name: "example.com",
    name_value: "example.com\nwww.example.com\napi.example.com",
  },
  {
    not_after: "2026-08-01T12:00:00.000Z",
    not_before: "2026-05-01T12:00:00.000Z",
    issuer_name: "Older CA",
    common_name: "example.com",
    name_value: "example.com",
  },
  {
    not_after: "2027-01-01T12:00:00.000Z",
    not_before: "2026-07-01T12:00:00.000Z",
    issuer_name: "Subdomain-only CA",
    common_name: "api.example.com",
    name_value: "api.example.com",
  },
];
const certSpotterBody = [
  {
    not_after: "2026-09-01T12:00:00.000Z",
    not_before: "2026-06-15T12:00:00.000Z",
    issuer: { name: "Spot CA" },
    dns_names: ["example.com", "app.example.com", "admin.example.com"],
  },
  {
    not_after: "2027-02-01T12:00:00.000Z",
    not_before: "2026-07-01T12:00:00.000Z",
    issuer: { name: "Subdomain-only Spot CA" },
    dns_names: ["api.example.com"],
  },
];

function providerFetcher({ crt = crtBody, certspotter = certSpotterBody, calls, urls = [] }) {
  return async (url) => {
    const value = String(url);
    urls.push(value);
    if (value.includes("crt.sh")) {
      calls.crt_sh++;
      if (crt instanceof Error) throw crt;
      return jsonResponse(crt);
    }
    if (value.includes("certspotter")) {
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
    const reservedSource = fs.readFileSync(
      path.join(root, "workers", "scan-api", "src", "engines", "reserved-scan.js"),
      "utf8"
    );
    eq("scan engine creates one per-scan CT cache",
      (scanEngineSource.match(/const ctCache = createCertificateTransparencyCache\(/g) || []).length,
      1);
    ok("default scan passes that cache to SSL and subdomains",
      /runSslModule\(domain, \{ accounting, signal, ctCache \}\)/.test(scanEngineSource) &&
        /runSubdomainsModule\(domain, \{ accounting, signal, ctCache \}\)/.test(scanEngineSource));
    ok("reserved scan reuses one cache for SSL and subdomains",
      /runReservedScan\(domain, \{ capacity, ctCache \}\)/.test(scanEngineSource) &&
        /runSslModule\(domain, \{ ctCache: sharedCtCache \}\)/.test(reservedSource) &&
        /runSubdomainsModule\(domain, \{ ctCache: sharedCtCache \}\)/.test(reservedSource));
  }

  // ── Successful provider results: one lookup and byte-stable consumers ─────
  const sharedCalls = { crt_sh: 0, certspotter: 0 };
  const sharedUrls = [];
  const shared = await runPair(providerFetcher({ calls: sharedCalls, urls: sharedUrls }));

  eq("shared scan performs one crt.sh fetch", sharedCalls.crt_sh, 1);
  eq("shared scan performs one CertSpotter fetch", sharedCalls.certspotter, 1);
  eq("shared crt.sh request is suffix-wide for both consumers",
    new URL(sharedUrls.find((url) => url.includes("crt.sh"))).searchParams.get("q"),
    "%example.com");
  ok("shared CertSpotter request includes subdomains and issuer data",
    /include_subdomains=true/.test(sharedUrls.find((url) => url.includes("certspotter"))) &&
      /expand=issuer/.test(sharedUrls.find((url) => url.includes("certspotter"))));
  eq("SSL selects the same longest-lived crt.sh certificate", shared.ssl.cert_not_after, crtBody[0].not_after);
  eq("SSL preserves the issuer", shared.ssl.cert_issuer, "Example Root CA");
  same("SSL preserves normalized SANs", shared.ssl.cert_san_names,
    ["example.com", "www.example.com", "api.example.com"]);
  eq("SSL preserves raw SAN count", shared.ssl.cert_raw_san_count, 3);
  eq("SSL preserves wildcard SAN count", shared.ssl.cert_wildcard_san_count, 0);
  eq("SSL preserves shared SAN count", shared.ssl.cert_shared_san_count, 0);
  eq("subdomains preserve merged count", shared.subdomains.count, 5);
  same("subdomains preserve sorted merged names", shared.subdomains.items,
    ["admin.example.com", "api.example.com", "app.example.com", "example.com", "www.example.com"]);
  same("subdomains preserve sensitive classification", shared.subdomains.sensitive,
    ["admin.example.com", "api.example.com", "app.example.com"]);
  same("subdomains preserve per-source success shape", shared.subdomains.sources, {
    crt_sh: { count: 3, error: null },
    certspotter: { count: 2, error: null },
  });

  const separateCalls = { crt_sh: 0, certspotter: 0 };
  const separate = await runPair(providerFetcher({ calls: separateCalls }), { shared: false });
  same("certificate fields are byte-identical to separate pre-cache consumption",
    certificateFields(shared.ssl), certificateFields(separate.ssl));
  same("subdomain result is byte-identical to separate pre-cache consumption",
    shared.subdomains, separate.subdomains);
  eq("separate pre-cache consumption demonstrates duplicate crt.sh calls",
    separateCalls.crt_sh, 2);
  eq("successful crt.sh still avoids SSL's CertSpotter fallback",
    separateCalls.certspotter, 1);

  // ── Cache key and in-flight promise contract ──────────────────────────────
  {
    const calls = { crt_sh: 0, certspotter: 0 };
    const cache = cacheFor(providerFetcher({ calls }));
    const first = cache.get("Example.COM.", "crt_sh");
    const second = cache.get("example.com", "crt_sh");
    ok("same normalized provider key reuses the in-flight promise", first === second);
    const [a, b] = await Promise.all([first, second]);
    ok("shared callers receive the same cached result object", a === b);
    eq("normalized key performs one provider fetch", calls.crt_sh, 1);
    eq("available provider status is explicit", a.status, "available");
    ok("available provider returns an array", Array.isArray(a.data));
    eq("available provider has no error", a.error, null);
  }

  {
    let fetchCalls = 0;
    const cache = cacheFor(async () => {
      fetchCalls++;
      throw new DOMException("provider timed out", "TimeoutError");
    });
    const timedOut = await cache.get("example.com", "crt_sh");
    eq("provider timeout is explicit unavailable", timedOut.status, "unavailable");
    eq("provider timeout never returns false-empty data", timedOut.data, null);
    eq("provider timeout retains a safe error", timedOut.error, "fetch failed");
    eq("provider timeout is cached after one fetch", fetchCalls, 1);
  }

  {
    let fetchCalls = 0;
    const cache = cacheFor(async () => {
      fetchCalls++;
      return jsonResponse([]);
    });
    const blocked = await cache.get("example.com", "crt_sh", {
      accounting: {
        assertCanIssue() { throw new DOMException("module budget exhausted", "AbortError"); },
      },
    });
    eq("pre-fetch cancellation becomes explicit unavailable", blocked.status, "unavailable");
    eq("pre-fetch cancellation never returns false-empty data", blocked.data, null);
    eq("pre-fetch cancellation issues no outbound request", fetchCalls, 0);
  }

  // ── crt.sh unavailable: explicit in both modules, shared fallback ─────────
  const fallbackCalls = { crt_sh: 0, certspotter: 0 };
  const fallback = await runPair(providerFetcher({
    calls: fallbackCalls,
    crt: new Error("crt.sh down"),
  }));

  eq("crt.sh-down scan still performs one crt.sh fetch", fallbackCalls.crt_sh, 1);
  eq("crt.sh-down scan performs one shared CertSpotter fallback", fallbackCalls.certspotter, 1);
  eq("SSL observes crt.sh as unavailable", fallback.ssl.ct_sources.crt_sh?.error, "fetch failed");
  eq("SSL observes CertSpotter fallback as available", fallback.ssl.ct_sources.certspotter?.error, null);
  eq("SSL fallback preserves certificate evidence", fallback.ssl.cert_issuer, "Spot CA");
  eq("subdomains observe crt.sh as unavailable", fallback.subdomains.sources.crt_sh.error, "fetch failed");
  eq("subdomains observe CertSpotter as available", fallback.subdomains.sources.certspotter.error, null);
  ok("subdomains retain fallback findings", fallback.subdomains.items.includes("app.example.com"));
  ok("one unavailable provider cannot certify discovery complete",
    subdomainDiscoveryComplete({
      subdomains: fallback.subdomains,
      dns_bruteforce: { items: [], error: null },
    }) === false);

  // ── Total blackout: unavailable is not successful empty or healthy ────────
  const blackoutCalls = { crt_sh: 0, certspotter: 0 };
  const blackout = await runPair(providerFetcher({
    calls: blackoutCalls,
    crt: new Error("crt.sh down"),
    certspotter: new Error("CertSpotter down"),
  }));
  eq("blackout still performs one crt.sh fetch", blackoutCalls.crt_sh, 1);
  eq("blackout still performs one CertSpotter fetch", blackoutCalls.certspotter, 1);
  eq("blackout leaves SSL certificate unknown", blackout.ssl.cert_not_after, null);
  eq("blackout exposes SSL crt.sh failure", blackout.ssl.ct_sources.crt_sh?.error, "fetch failed");
  eq("blackout exposes SSL CertSpotter failure", blackout.ssl.ct_sources.certspotter?.error, "fetch failed");
  eq("blackout exposes subdomain crt.sh failure", blackout.subdomains.sources.crt_sh.error, "fetch failed");
  eq("blackout exposes subdomain CertSpotter failure", blackout.subdomains.sources.certspotter.error, "fetch failed");
  ok("blackout carries the existing CT diagnostic", blackout.subdomains.ct_error?.startsWith("Both CT sources failed"));
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
  const emptyCalls = { crt_sh: 0, certspotter: 0 };
  const empty = await runPair(providerFetcher({
    calls: emptyCalls,
    crt: [],
    certspotter: [],
  }));
  eq("successful-empty crt.sh has no SSL provider error", empty.ssl.ct_sources.crt_sh?.error, null);
  eq("successful-empty CertSpotter has no SSL provider error", empty.ssl.ct_sources.certspotter?.error, null);
  eq("successful-empty crt.sh has no subdomain provider error", empty.subdomains.sources.crt_sh.error, null);
  eq("successful-empty CertSpotter has no subdomain provider error", empty.subdomains.sources.certspotter.error, null);
  ok("successful-empty result does not claim a provider blackout", !empty.subdomains.ct_error);
  eq("successful-empty still performs one crt.sh fetch", emptyCalls.crt_sh, 1);
  eq("successful-empty still performs one CertSpotter fetch", emptyCalls.certspotter, 1);

  // Execute both defect-class mutations. Each nested validator must turn red.
  if (!breakSharing && !falseEmpty) {
    const sharingMutation = spawnSync(process.execPath, [scriptPath, "--mutate-break-sharing"], {
      cwd: root,
      encoding: "utf8",
    });
    ok("mutation: breaking cache sharing makes the validator RED",
      sharingMutation.status !== 0 &&
        sharingMutation.stdout.includes("FAIL shared scan performs one crt.sh fetch"));

    const failureMutation = spawnSync(process.execPath, [scriptPath, "--mutate-failure-to-empty"], {
      cwd: root,
      encoding: "utf8",
    });
    ok("mutation: converting unavailable to empty-as-healthy makes the validator RED",
      failureMutation.status !== 0 &&
        failureMutation.stdout.includes("FAIL SSL observes crt.sh as unavailable"));
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
