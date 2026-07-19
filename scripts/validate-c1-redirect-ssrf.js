#!/usr/bin/env node
//
// C1 — redirect-chain SSRF in the default asset prober. CI-blocking. Node 24+.
//
// The legacy defaultProbeFetch (default-active when SCAN_CAPACITY_MODE is unset)
// followed redirects natively with no per-hop validation, so a public asset that
// 302'd to an internal address — or whose A record pointed at a private IP — was
// fetched. This proves defaultProbeFetch now routes through the shared
// makeSsrfSafeProbeFetch core: bounded MANUAL redirects, every hop validated by the
// canonical ssrf.js guards (scheme/credentials/private-reserved literal + DNS-answer
// rebinding), fail-closed to null (probeAsset → reachable:false, never healthy).
//
// Section A: behavioural, driving the real fetcher with a mock fetch + mock resolver.
// Section B: self-proving source guards — each predicate holds on real source AND fails
//            on an in-memory copy with the defect reintroduced (the required mutations).
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const imp = (rel) => import(pathToFileURL(path.join(root, "workers", "scan-api", "src", rel)).href);
const read = (rel) => fs.readFileSync(path.join(root, "workers", "scan-api", "src", rel), "utf8");

const { hostIsPrivateOrReserved, urlIsBlockedTarget } = await imp("lib/ssrf.js");
const { makeSsrfSafeProbeFetch } = await imp("engines/reserved-probe.js");
const { probeAsset } = await imp("engines/asset-intel.js");

let pass = 0, fail = 0;
const ok = (name, cond) => { cond ? pass++ : fail++; if (!cond) console.log("FAIL " + name); };

// ── Mock fetch: a routing table url → { status, location } ────────────────────
let ROUTES = {};
const realFetch = globalThis.fetch;
globalThis.fetch = async (url) => {
  const r = ROUTES[String(url)] ?? ROUTES["*"] ?? { status: 200 };
  const headers = r.location ? { location: r.location } : {};
  return new Response(null, { status: r.status ?? 200, headers });
};
// Resolver: hostname → list of IPs (defaults public). Never throws.
let DNS = {};
const resolver = async (name) => {
  const ips = DNS[name] ?? ["93.184.216.34"]; // example.com, public
  return { Answer: ips.map((ip) => ({ data: ip })) };
};
const fetcher = makeSsrfSafeProbeFetch({ resolver, maxHops: 3, timeoutMs: 1000 });

async function run() {
  // 1. public → public allowed (200 returned)
  ROUTES = { "http://pub.example/": { status: 200 } }; DNS = {};
  ok("public → public allowed", (await fetcher("http://pub.example/"))?.status === 200);

  // 2. public → loopback blocked (redirect Location to 127.0.0.1)
  ROUTES = { "http://pub.example/": { status: 302, location: "http://127.0.0.1/" } };
  ok("public → loopback redirect blocked", (await fetcher("http://pub.example/")) === null);

  // 3. public → RFC1918 blocked
  ROUTES = { "http://pub.example/": { status: 302, location: "http://10.0.0.5/" } };
  ok("public → RFC1918 redirect blocked", (await fetcher("http://pub.example/")) === null);

  // 4. public → metadata blocked
  ROUTES = { "http://pub.example/": { status: 302, location: "http://169.254.169.254/latest/meta-data/" } };
  ok("public → metadata redirect blocked", (await fetcher("http://pub.example/")) === null);

  // 5. public → IPv6 loopback blocked
  ROUTES = { "http://pub.example/": { status: 302, location: "http://[::1]/" } };
  ok("public → IPv6 loopback redirect blocked", (await fetcher("http://pub.example/")) === null);

  // 6. public → IPv6 ULA / link-local blocked
  ROUTES = { "http://pub.example/": { status: 302, location: "http://[fd00::1]/" } };
  ok("public → IPv6 ULA redirect blocked", (await fetcher("http://pub.example/")) === null);
  ROUTES = { "http://pub.example/": { status: 302, location: "http://[fe80::1]/" } };
  ok("public → IPv6 link-local redirect blocked", (await fetcher("http://pub.example/")) === null);

  // 7. IPv4-mapped private IPv6 blocked (literal)
  ok("IPv4-mapped private IPv6 literal blocked", hostIsPrivateOrReserved("::ffff:10.0.0.1") === true);
  ok("IPv4-mapped metadata IPv6 literal blocked", hostIsPrivateOrReserved("::ffff:169.254.169.254") === true);
  ok("IPv4-mapped public IPv6 literal allowed", hostIsPrivateOrReserved("::ffff:93.184.216.34") === false);

  // 8. relative public redirect allowed
  ROUTES = { "http://pub.example/": { status: 302, location: "/next" }, "http://pub.example/next": { status: 200 } };
  ok("relative public redirect followed to 200", (await fetcher("http://pub.example/"))?.status === 200);

  // 9. malformed Location not followed (returns the 3xx, never fetches a bad target).
  // Invalid port → new URL(loc, base) throws → the core returns the 3xx unfollowed.
  ROUTES = { "http://pub.example/": { status: 302, location: "http://pub.example:999999/" } };
  { const r = await fetcher("http://pub.example/"); ok("malformed Location not followed", r !== null && r.status === 302); }

  // 10. redirect loop bounded (a→a…) terminates, returns the 3xx, never loops forever
  ROUTES = { "http://loop.example/": { status: 302, location: "http://loop.example/" } };
  DNS = { "loop.example": ["93.184.216.34"] };
  { const r = await fetcher("http://loop.example/"); ok("redirect loop bounded", r !== null && r.status === 302); }

  // 11. ftp/file/data/javascript redirect blocked
  for (const scheme of ["ftp://x.example/", "file:///etc/passwd", "data:text/html,x", "javascript:alert(1)"]) {
    ROUTES = { "http://pub.example/": { status: 302, location: scheme } };
    ok(`redirect to ${scheme.split(":")[0]} blocked`, (await fetcher("http://pub.example/")) === null);
  }

  // 12. URL credentials blocked (initial hop)
  ok("URL credentials blocked", (await fetcher("http://user:pass@pub.example/")) === null);

  // 13. mixed DNS answer containing a prohibited address blocked (rebinding)
  ROUTES = { "http://rebind.example/": { status: 200 } };
  DNS = { "rebind.example": ["93.184.216.34", "10.1.2.3"] }; // one public, one private
  ok("mixed DNS answer (one private) blocked", (await fetcher("http://rebind.example/")) === null);

  // 14. host resolving entirely to a private IP blocked
  DNS = { "internal.example": ["192.168.1.10"] };
  ROUTES = { "http://internal.example/": { status: 200 } };
  ok("host resolving to RFC1918 blocked", (await fetcher("http://internal.example/")) === null);

  // 15. a blocked fetch can never become healthy — probeAsset maps null → reachable:false
  DNS = {};
  const blocked = await probeAsset("blocked.example", { fetcher: async () => null });
  ok("blocked probe is reachable:false (never healthy)", blocked.reachable === false);
  ok("blocked probe carries no assessed-healthy signal", blocked.reachable !== true && !blocked.probe_status);

  // 16. non-redirect path unchanged: a normal 200 with a fetcher still returns the asset
  const good = await probeAsset("ok.example", { fetcher: async () => new Response("<title>Hi</title>", { status: 200, headers: { "content-type": "text/html" } }) });
  ok("non-redirect 200 still assessed reachable", good.reachable === true && good.status === 200);
}

await run();
globalThis.fetch = realFetch;

// ── Section B: self-proving source guards (the required mutation set) ──────────
const ssrfSrc = read("lib/ssrf.js");
const rpSrc   = read("engines/reserved-probe.js");
const aiSrc   = read("engines/asset-intel.js");

function guard(name, src, predicate, mutate) {
  ok(`${name} — holds on current source`, predicate(src) === true);
  const mutated = mutate(src);
  ok(`${name} — mutation changed source`, mutated !== src);
  ok(`${name} — CAUGHT when defect reintroduced`, predicate(mutated) === false);
}

// redirect mode changed to follow
guard("core follows redirects MANUALLY", rpSrc,
  (s) => /redirect:\s*"manual"/.test(s.split("makeSsrfSafeProbeFetch")[1] || ""),
  (s) => s.replace('redirect: "manual"', 'redirect: "follow"'));
// per-hop URL (scheme/creds/literal) validation removed
guard("core validates every hop with urlIsBlockedTarget", rpSrc,
  (s) => /if \(urlIsBlockedTarget\(current\)\) return null;/.test(s),
  (s) => s.replace("if (urlIsBlockedTarget(current)) return null;", ""));
// per-hop DNS rebinding validation removed
guard("core validates every hop with resolvesToPrivateIp", rpSrc,
  (s) => /if \(await resolvesToPrivateIp\(hostname, resolver\)\) return null;/.test(s),
  (s) => s.replace("if (await resolvesToPrivateIp(hostname, resolver)) return null;", ""));
// redirect limit removed
guard("core enforces a redirect hop cap", rpSrc,
  (s) => /hop >= maxHops/.test(s),
  (s) => s.replace("hop >= maxHops", "false"));
// private IPv4 check removed
guard("ssrf blocks private IPv4 literals", ssrfSrc,
  (s) => /127\\\.\|10\\\.\|192\\\.168\\\./.test(s),
  (s) => s.replace(/127\\\.\|10\\\.\|192\\\.168\\\.\|169\\\.254\\\.\|172\\\.\(1\[6-9\]\|2\\d\|3\[01\]\)\\\.\|100\\\.\(6\[4-9\]\|\[7-9\]\\d\|1\[01\]\\d\|12\[0-7\]\)\\\./, "999\\."));
// IPv6 private check removed
guard("ssrf blocks IPv6 loopback/ULA/link-local", ssrfSrc,
  (s) => /host === "::1"/.test(s) && /f\[cd\]\[0-9a-f\]\*:/.test(s),
  (s) => s.replace('host === "::1" || host === "::" || /^f[cd][0-9a-f]*:/i.test(host) || /^fe[89ab][0-9a-f]:/i.test(host)', "false"));
// metadata block removed (169.254 covers 169.254.169.254)
guard("ssrf blocks link-local incl. metadata", ssrfSrc,
  (s) => /169\\\.254\\\./.test(s),
  (s) => s.replace("169\\.254\\.|", ""));
// protocol check removed
guard("ssrf blocks non-http(s) schemes", ssrfSrc,
  (s) => /u\.protocol !== "http:" && u\.protocol !== "https:"/.test(s),
  (s) => s.replace('if (u.protocol !== "http:" && u.protocol !== "https:") return true;', ""));
// IPv4-mapped IPv6 decode removed
guard("ssrf decodes IPv4-mapped IPv6", ssrfSrc,
  (s) => /if \(v4mappedDotted\) return hostIsPrivateOrReserved\(v4mappedDotted\[1\]\);/.test(s),
  (s) => s.replace("if (v4mappedDotted) return hostIsPrivateOrReserved(v4mappedDotted[1]);", ""));
// defaultProbeFetch actually uses the SSRF-safe core (not native follow)
guard("defaultProbeFetch uses the SSRF-safe core", aiSrc,
  (s) => /const defaultProbeFetch = makeSsrfSafeProbeFetch\(/.test(s) && !/function defaultProbeFetch\(url\) \{\s*return fetch\(url, \{\s*method:\s*"GET",\s*redirect:\s*"follow"/.test(s),
  (s) => s.replace("const defaultProbeFetch = makeSsrfSafeProbeFetch(", 'function defaultProbeFetch(url) { return fetch(url, { redirect: "follow" }); } const _x = (('));

console.log(`\nC1 redirect SSRF: ${pass}/${pass + fail} passed`);
if (fail) { console.error("c1-redirect-ssrf validation FAILED"); process.exit(1); }
console.log("c1-redirect-ssrf validation passed");
