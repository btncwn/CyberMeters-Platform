#!/usr/bin/env node
//
// SSRF input-gate safety (internal pentest §20/§32 — locked as regression).
// The scan engine and the PUBLIC free-scan fetch arbitrary user-supplied targets,
// so the domain gate is the first SSRF defense: it must reject IP literals,
// localhost, the cloud-metadata address, IPv6, ports and URL schemes BEFORE any
// outbound request is made. (Defence-in-depth: the Cloudflare Workers runtime
// also blocks private-range egress and has no metadata endpoint — but the app
// gate must not rely on that alone.) Both /api/scan and public /api/free-scan
// enforce isValidDomain. Requires Node 24+ (node:sqlite). CI-blocking.
//
import fs from "node:fs";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const { isValidDomain } = await import(pathToFileURL(path.join(root, "workers", "scan-api", "src", "lib", "util.js")).href);
const { billingRoutes } = await import(pathToFileURL(path.join(root, "workers", "scan-api", "src", "routes", "billing.js")).href);
const { safeFetch } = await import(
  pathToFileURL(path.join(root, "workers", "scan-api", "src", "lib", "http.js")).href
);
const { consumeApiRateLimit: canonicalConsumeApiRateLimit } = await import(
  pathToFileURL(path.join(root, "workers", "scan-api", "src", "lib", "rate-limit.js")).href
);
const { dnsQuery: productionDnsQuery } = await import(
  pathToFileURL(path.join(root, "workers", "scan-api", "src", "engines", "dns.js")).href
);

let pass = 0, fail = 0;
const ok = (name, cond) => { cond ? pass++ : fail++; if (!cond) console.log("FAIL " + name); };
const eq = (name, actual, expected) =>
  ok(name, actual === expected);

// ── 1. Unit: the domain gate rejects every SSRF target class ─────────────────
const SSRF_TARGETS = [
  "169.254.169.254",        // AWS/GCP metadata IP
  "127.0.0.1", "0.0.0.0", "10.0.0.1", "192.168.1.1", "172.16.0.1", // private/loopback IPv4
  "localhost", "metadata", "metadata.google.internal", // hostnames (single-label / internal)
  "[::1]", "::1", "fd00::1", // IPv6
  "2130706433",             // decimal-encoded 127.0.0.1
  "0x7f000001",             // hex-encoded 127.0.0.1
  "127.0.0.1:8080", "example.com:22", // host:port
  "http://169.254.169.254/", "https://localhost/", "file:///etc/passwd", // URL schemes
  "example.com/../admin", "example.com#@evil.com", "example.com?@evil", // path/fragment tricks
  "example.com evil.com", "a b.com", // whitespace injection
];
for (const t of SSRF_TARGETS) ok(`gate rejects SSRF target: ${t}`, isValidDomain(t) === false);

// Positive control: real public domains still pass (no false negatives).
// (IDN/punycode `xn--` TLDs are intentionally unsupported — not a security gap.)
for (const t of ["example.com", "blackbullbarbers.co.uk", "sub.domain.example.org", "a-b.co.uk"]) {
  ok(`gate allows legitimate domain: ${t}`, isValidDomain(t) === true);
}
// Reserved / private-use TLDs are rejected (SSRF pivots, not publicly resolvable).
for (const t of ["x.internal", "host.local", "app.localhost", "server.corp", "db.lan"]) {
  ok(`gate rejects reserved-TLD host: ${t}`, isValidDomain(t) === false);
}

// ── 2. Integration: public /api/free-scan refuses an SSRF target pre-fetch ────
globalThis.fetch = async () => { throw new Error("network disabled — a scan should never start for a rejected domain"); };
AbortSignal.timeout = () => undefined;
const worker = await import(pathToFileURL(path.join(root, "workers", "scan-api", "src", "index.js")).href);

const db = new DatabaseSync(":memory:");
const apply = (p) => { try { db.exec(fs.readFileSync(p, "utf8")); } catch { /* ordering no-ops */ } };
apply(path.join(root, "database", "schema.sql"));
for (const f of fs.readdirSync(path.join(root, "database", "migrations")).filter((f) => f.endsWith(".sql")).sort()) apply(path.join(root, "database", "migrations", f));
const makeD1 = (db) => {
  const wrap = (sql, args) => ({ first: async () => db.prepare(sql).get(...args) ?? null, all: async () => ({ results: db.prepare(sql).all(...args) }), run: async () => { const r = db.prepare(sql).run(...args); return { meta: { changes: r.changes } }; } });
  return { prepare(sql) { const b = wrap(sql, []); b.bind = (...a) => wrap(sql, a); return b; } };
};
const env = {
  cybermeters_db: makeD1(db),
  cybermeters_reports: { get: async () => null, put: async () => ({}), head: async () => null, delete: async () => ({}), list: async () => ({ objects: [] }) },
  ALLOWED_ORIGIN: "https://app.cybermeters.com", APP_VERSION: "test",
};
const ctx = { waitUntil: () => {}, passThroughOnException: () => {} };
const freeScan = async (domain) => {
  const res = await worker.default.fetch(new Request("https://app.cybermeters.com/api/free-scan", {
    method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ domain }),
  }), env, ctx);
  let body = {}; try { body = await res.json(); } catch { /* */ }
  return { status: res.status, body };
};

for (const t of ["169.254.169.254", "localhost", "http://127.0.0.1/", "file:///etc/passwd"]) {
  const r = await freeScan(t);
  ok(`free-scan rejects SSRF target ${t} with 4xx (no scan started)`, r.status >= 400 && r.status < 500);
}

// ── 3. Public preview guardrails: rebinding, fail-closed throttle, no storage ─
const safeModuleResults = {
  dns: {
    resolves: true,
    resolves_any: true,
    resolution_assessed: true,
    has_mx: true,
    cross_checks: { resolver_agreement_score: 100 },
    dnssec: {
      errors: { ds: null, dnskey: null, rrsig: null },
      ds: { present: true },
      dnskey: { present: true },
      rrsig: { present: true },
    },
  },
  ssl: {
    https_available: true,
    https_probe_executed: true,
    http_redirects_to_https: true,
    http_redirect_chain: { http_redirect_validated: true },
  },
  headers: {
    accessible: true,
    headers_assessed: true,
    status_code: 200,
    final_https: true,
    values: {
      "strict-transport-security": "max-age=31536000; includeSubDomains",
      "content-security-policy": "default-src 'self'",
      "x-frame-options": "DENY",
      "x-content-type-options": "nosniff",
      "referrer-policy": "strict-origin",
      "permissions-policy": "camera=(), microphone=()",
    },
  },
  email_security: {
    spf_evidence_status: "observed",
    dkim_evidence_status: "observed",
    dmarc_state: { evidence_status: "observed" },
    spf: { present: true },
    dkim: { present: true, selectors_probed: ["selector1"] },
    dmarc: { present: true, policy: "reject", record: "v=DMARC1; p=reject" },
  },
  subdomains: { count: 0, items: [], sensitive: [], sources: {} },
  technology_detection: { status_code: 200, technologies: [], external_scripts: [] },
};

async function runDirectPreview({
  denyOperation = null,
  privateAnswer = false,
  resolverUnavailable = false,
  addressMode = "dual",
  dnsQueryImpl = null,
  moduleBehaviors = {},
} = {}) {
  const rateCalls = [];
  const moduleOptions = {};
  let moduleCalls = 0;
  let storageTouches = 0;
  const forbiddenStorage = new Proxy({}, {
    get() {
      storageTouches += 1;
      throw new Error("anonymous preview attempted persistent storage access");
    },
  });
  const directEnv = {
    cybermeters_db: forbiddenStorage,
    cybermeters_reports: forbiddenStorage,
  };
  const directRequest = new Request("https://app.cybermeters.com/api/free-scan", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "CF-Connecting-IP": "198.51.100.42",
    },
    body: JSON.stringify({ domain: "example.com" }),
  });
  const response = await billingRoutes({
    request: directRequest,
    url: new URL(directRequest.url),
    env: directEnv,
    json: (body, status = 200) => Response.json(body, { status }),
    serverError: (_area, error) => Response.json({ error: error?.message }, { status: 500 }),
    requireAuth: async () => null,
    requireWorkspaceRole: async () => null,
    rateLimitScopeId: async (kind, value) => `${kind}:${value}`,
    consumeApiRateLimit: async (_env, scopes, operation, limit, windowSeconds, options) => {
      rateCalls.push({ scopes, operation, limit, windowSeconds, options });
      return operation === denyOperation ? { limited: true } : null;
    },
    freeScanDnsQuery: dnsQueryImpl || (async (name, type) => {
      if (resolverUnavailable) throw new Error("resolver unavailable");
      const privateTarget = privateAnswer || name === "rebind.example";
      const familyEnabled = addressMode === "dual"
        || (addressMode === "a_only" && type === "A")
        || (addressMode === "aaaa_only" && type === "AAAA");
      return {
        Status: 0,
        TC: false,
        Answer: !familyEnabled
          ? []
          : type === "A"
            ? [{ type: 1, data: privateTarget ? "10.0.0.9" : "8.8.8.8" }]
            : [{ type: 28, data: "2606:4700:4700::1111" }],
      };
    }),
    freeScanModuleRunners: Object.fromEntries(
      Object.entries(safeModuleResults).map(([module, value]) => [
        module,
        async (_domain, options) => {
          moduleCalls += 1;
          moduleOptions[module] = options;
          if (typeof moduleBehaviors[module] === "function") {
            return moduleBehaviors[module](_domain, options);
          }
          return structuredClone(value);
        },
      ]),
    ),
  });
  return {
    status: response.status,
    body: await response.json(),
    rateCalls,
    moduleCalls,
    moduleOptions,
    storageTouches,
  };
}

const rebound = await runDirectPreview({ privateAnswer: true });
eq("DNS-answer rebinding target is refused", rebound.status, 400);
eq("DNS-answer rebinding target launches zero modules", rebound.moduleCalls, 0);
eq("DNS-answer rebinding refusal touches no persistence", rebound.storageTouches, 0);

const resolverDown = await runDirectPreview({ resolverUnavailable: true });
eq("resolver unavailability fails the public route closed", resolverDown.status, 503);
eq("resolver unavailability launches zero modules", resolverDown.moduleCalls, 0);
eq("resolver unavailability returns an explicit verification code",
  resolverDown.body.code, "target_verification_unavailable");

for (const addressMode of ["a_only", "aaaa_only"]) {
  const singleFamily = await runDirectPreview({ addressMode });
  eq(`${addressMode} public domain is admitted`, singleFamily.status, 200);
  eq(`${addressMode} public domain launches the six bounded modules`,
    singleFamily.moduleCalls, 6);
}
const noAddress = await runDirectPreview({ addressMode: "none" });
eq("both-families NODATA remains fail-closed", noAddress.status, 503);
eq("both-families NODATA launches zero modules", noAddress.moduleCalls, 0);

for (const [operation, expectedCalls] of [
  ["free_scan", 1],
  ["free_scan_domain", 2],
  ["free_scan_global", 3],
]) {
  const limited = await runDirectPreview({ denyOperation: operation });
  eq(`${operation} denial returns 429`, limited.status, 429);
  eq(`${operation} denial stops before modules`, limited.moduleCalls, 0);
  eq(`${operation} denial stops at the expected throttle`, limited.rateCalls.length, expectedCalls);
  ok(`${operation} throttle is explicitly fail-closed`,
    limited.rateCalls.every((call) => call.options?.failClosed === true));
  ok(`${operation} throttle is explicitly atomic`,
    limited.rateCalls.every((call) => call.options?.atomic === true));
  eq(`${operation} denial touches no persistence outside rate-limit adapter`,
    limited.storageTouches, 0);
}

const allowedPreview = await runDirectPreview();
eq("allowed preview runs all six bounded modules", allowedPreview.moduleCalls, 6);
eq("allowed preview evaluates all three throttles", allowedPreview.rateCalls.length, 3);
eq("allowed preview returns persistence:none", allowedPreview.body.persistence, "none");
eq("allowed preview touches no D1/R2 scan/report persistence", allowedPreview.storageTouches, 0);
eq("allowed preview returns exactly eight domain cards",
  allowedPreview.body.cyber_mot_domains?.length, 8);
ok("headers receives a live remaining-time carrier",
  typeof allowedPreview.moduleOptions.headers?.remainingMs === "function");
const initialRemainingMs = allowedPreview.moduleOptions.headers?.remainingMs?.();
ok("remaining-time carrier is bounded by the public 20s deadline",
  Number.isFinite(initialRemainingMs) && initialRemainingMs >= 0 && initialRemainingMs <= 20_000);
eq("DNS and email share one per-snapshot DNS cache",
  allowedPreview.moduleOptions.dns?.cache,
  allowedPreview.moduleOptions.email_security?.cache);
eq("TLS and subdomains share one per-snapshot CT cache",
  allowedPreview.moduleOptions.ssl?.ctCache,
  allowedPreview.moduleOptions.subdomains?.ctCache);
for (const module of ["ssl", "headers", "technology_detection"]) {
  ok(`${module} receives the strict per-hop DNS resolver`,
    typeof allowedPreview.moduleOptions[module]?.dnsResolver === "function");
  eq(`${module} receives the shared in-flight-only safety cache`,
    allowedPreview.moduleOptions[module]?.dnsCache,
    allowedPreview.moduleOptions.ssl?.dnsCache);
}
ok("HTTP safety cache is isolated from the completed evidence cache",
  allowedPreview.moduleOptions.ssl?.dnsCache !== allowedPreview.moduleOptions.dns?.cache);
let reboundFetches = 0;
const reboundFetch = await safeFetch("https://rebind.example", {
  dnsResolver: allowedPreview.moduleOptions.ssl?.dnsResolver,
  dnsCache: allowedPreview.moduleOptions.ssl?.dnsCache,
  fetchImpl: async () => {
    reboundFetches += 1;
    return new Response("should not be reached", { status: 200 });
  },
});
eq("per-hop strict resolver refuses a private rebinding answer", reboundFetch, null);
eq("private rebinding answer reaches no HTTP fetch sink", reboundFetches, 0);

async function runSameHostRedirectSafetyProbe({ privateOnRedirect }) {
  const originalFetch = globalThis.fetch;
  const dohCalls = { A: 0, AAAA: 0 };
  let httpFetches = 0;
  try {
    globalThis.fetch = async (rawUrl) => {
      const url = new URL(String(rawUrl));
      const type = url.searchParams.get("type");
      if (url.hostname !== "cloudflare-dns.com" || !Object.hasOwn(dohCalls, type)) {
        throw new Error(`unexpected network request ${url}`);
      }
      dohCalls[type] += 1;
      const redirectResolution = dohCalls[type] >= 3;
      const data = type === "A"
        ? (privateOnRedirect && redirectResolution ? "10.0.0.9" : "8.8.8.8")
        : (privateOnRedirect && redirectResolution ? "fd00::9" : "2606:4700:4700::1111");
      return Response.json({
        Status: 0,
        TC: false,
        Answer: [{ type: type === "A" ? 1 : 28, data }],
      });
    };
    const result = await runDirectPreview({
      dnsQueryImpl: productionDnsQuery,
      moduleBehaviors: {
        ssl: async (_domain, options) => {
          const response = await safeFetch("https://example.com/start", {
            dnsResolver: options.dnsResolver,
            dnsCache: options.dnsCache,
            accounting: options.accounting,
            signal: options.signal,
            fetchImpl: async () => {
              httpFetches += 1;
              return httpFetches === 1
                ? new Response("", { status: 302, headers: { location: "https://example.com/next" } })
                : new Response("ok", { status: 200 });
            },
          });
          return {
            ...safeModuleResults.ssl,
            https_available: response?.status === 200,
          };
        },
      },
    });
    return { result, dohCalls, httpFetches };
  } finally {
    globalThis.fetch = originalFetch;
  }
}

const sameHostRebind = await runSameHostRedirectSafetyProbe({ privateOnRedirect: true });
eq("same-host redirect re-resolves A on every safety decision", sameHostRebind.dohCalls.A, 3);
eq("same-host redirect re-resolves AAAA on every safety decision", sameHostRebind.dohCalls.AAAA, 3);
eq("same-host private rebound blocks the second HTTP fetch", sameHostRebind.httpFetches, 1);
eq("same-host private rebound keeps the bounded preview response honest", sameHostRebind.result.status, 200);

const sameHostPublic = await runSameHostRedirectSafetyProbe({ privateOnRedirect: false });
eq("same-host public redirect re-resolves A on every safety decision", sameHostPublic.dohCalls.A, 3);
eq("same-host public redirect re-resolves AAAA on every safety decision", sameHostPublic.dohCalls.AAAA, 3);
eq("same-host public redirect reaches the intended second HTTP fetch", sameHostPublic.httpFetches, 2);
eq("same-host public redirect remains admitted", sameHostPublic.result.status, 200);

// The route assertion above proves every public-preview guard selects the
// canonical atomic path. This concurrent claim proves that path admits only
// the configured number of requests even when several callers race the same
// scope/window; later claims must receive the fail-closed 429 verdict.
const raceDb = new DatabaseSync(":memory:");
raceDb.exec(`
  CREATE TABLE api_rate_limits (
    id TEXT PRIMARY KEY,
    scope TEXT NOT NULL,
    scope_id TEXT NOT NULL,
    action TEXT NOT NULL,
    window_start TEXT NOT NULL,
    window_seconds INTEGER NOT NULL,
    request_count INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
  );
`);
const raceResults = await Promise.all(
  Array.from({ length: 8 }, () => canonicalConsumeApiRateLimit(
    { cybermeters_db: makeD1(raceDb) },
    [{ scope: "domain", scope_id: "same-public-target" }],
    "free_scan_domain_atomic_probe",
    3,
    3600,
    { failClosed: true, atomic: true },
  )),
);
eq("atomic concurrency probe admits only the configured three claims",
  raceResults.filter((result) => result == null).length, 3);
eq("atomic concurrency probe rejects every over-limit claim",
  raceResults.filter((result) => result?.status === 429).length, 5);
eq("atomic concurrency probe records every attempted claim",
  raceDb.prepare("SELECT request_count FROM api_rate_limits").get()?.request_count, 8);

console.log(`\nSSRF domain guard: ${pass}/${pass + fail} passed`);
if (fail) { console.error("ssrf-domain-guard validation FAILED"); process.exit(1); }
console.log("ssrf-domain-guard validation passed");
