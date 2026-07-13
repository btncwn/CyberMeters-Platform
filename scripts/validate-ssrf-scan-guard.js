#!/usr/bin/env node
//
// SSRF scan-guard proof (P0 #3a). The string input-gate only vets the initial
// user string; this covers the two vectors it can't: (a) redirect-time SSRF (a
// public domain 302s to an internal address) and (b) a public domain whose A
// record resolves to a private IP. Drives the host classifier, urlIsBlockedTarget,
// resolvesToPrivateIp, and the SSRF-aware safeFetch (per-hop validation + manual
// redirect following) against a stubbed fetch. Node 24+. CI-blocking.
//
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const ssrf = await import(pathToFileURL(path.join(root, "workers", "scan-api", "src", "lib", "ssrf.js")).href);
const { hostIsPrivateOrReserved, urlIsBlockedTarget, resolvesToPrivateIp } = ssrf;

let pass = 0, fail = 0;
const ok = (name, cond) => { cond ? pass++ : fail++; if (!cond) console.log("FAIL " + name); };

// ── Host classifier ──────────────────────────────────────────────────────────
for (const h of ["127.0.0.1", "10.0.0.5", "192.168.1.1", "169.254.169.254", "172.16.0.1",
                 "172.31.255.1", "0.0.0.0", "localhost", "svc.internal", "printer.local",
                 "metadata", "2130706433", "::1", "::", "fc00::1", "fd12::9", "fe80::1"]) {
  ok(`blocks private/reserved host: ${h}`, hostIsPrivateOrReserved(h) === true);
}
for (const h of ["example.com", "www.example.com", "1.1.1.1", "8.8.8.8", "d3.cloudfront.net",
                 "sub.domain.co.uk", "172.15.0.1", "172.32.0.1", "11.0.0.1"]) {
  ok(`allows public host: ${h}`, hostIsPrivateOrReserved(h) === false);
}

// ── urlIsBlockedTarget ───────────────────────────────────────────────────────
ok("blocks http://169.254.169.254/", urlIsBlockedTarget("http://169.254.169.254/") === true);
ok("blocks http://localhost:8080/x", urlIsBlockedTarget("http://localhost:8080/x") === true);
ok("blocks credentials in URL", urlIsBlockedTarget("http://user:pass@example.com/") === true);
ok("blocks non-http scheme", urlIsBlockedTarget("ftp://example.com/") === true);
ok("blocks malformed URL", urlIsBlockedTarget("::::not a url") === true);
ok("allows https://example.com/", urlIsBlockedTarget("https://example.com/") === false);
ok("allows http public with path", urlIsBlockedTarget("http://scan-me.example.org/a/b") === false);

// ── resolvesToPrivateIp ──────────────────────────────────────────────────────
const dohPrivate = async (_n, t) => ({ Answer: t === "A" ? [{ data: "10.1.2.3" }] : [] });
const dohPublic  = async (_n, t) => ({ Answer: t === "A" ? [{ data: "93.184.216.34" }] : [] });
const dohMixed   = async (_n, t) => ({ Answer: t === "A" ? [{ data: "93.184.216.34" }, { data: "127.0.0.1" }] : [] });
const dohError   = async () => { throw new Error("DoH down"); };
ok("private A record → blocked", (await resolvesToPrivateIp("evil.example", dohPrivate)) === true);
ok("public A record → allowed", (await resolvesToPrivateIp("good.example", dohPublic)) === false);
ok("ANY private answer → blocked", (await resolvesToPrivateIp("evil.example", dohMixed)) === true);
ok("resolver error fails OPEN (never blocks a scan on DoH failure)", (await resolvesToPrivateIp("x.example", dohError)) === false);
ok("no resolver provided → allowed (guard off)", (await resolvesToPrivateIp("x.example", null)) === false);

// ── safeFetch: per-hop validation + manual redirect following ─────────────────
const { safeFetch } = await import(pathToFileURL(path.join(root, "workers", "scan-api", "src", "lib", "http.js")).href);
const resp = (status, location = null) => ({ status, url: "", headers: { get: (k) => (k.toLowerCase() === "location" ? location : null) } });
let fetchCalls = [];
function stubFetch(routes) {
  fetchCalls = [];
  globalThis.fetch = async (u) => { fetchCalls.push(String(u)); return routes[String(u)] || resp(200); };
}

// 1. A public target that 302s to a private IP literal → refused mid-chain.
stubFetch({ "http://pub.example.com/": resp(302, "http://169.254.169.254/latest/meta-data/") });
ok("redirect to internal IP is refused (returns null)", (await safeFetch("http://pub.example.com/", { redirect: "follow" })) === null);
ok("the internal redirect target is NEVER fetched", !fetchCalls.includes("http://169.254.169.254/latest/meta-data/"));

// 2. A public→public redirect is followed to the final response.
stubFetch({ "https://a.example.com/": resp(302, "https://final.example.com/"), "https://final.example.com/": resp(200) });
const followed = await safeFetch("https://a.example.com/", { redirect: "follow" });
ok("public redirect chain is followed to the final 200", followed?.status === 200 && fetchCalls.includes("https://final.example.com/"));

// 3. A directly-private target is blocked before any fetch happens.
stubFetch({});
ok("direct private target returns null", (await safeFetch("http://10.0.0.9/admin", { redirect: "follow" })) === null);
ok("no fetch is issued for a blocked target", fetchCalls.length === 0);

// 4. redirect:"manual" keeps single-hop semantics (caller reads Location itself).
stubFetch({ "https://m.example.com/": resp(301, "https://elsewhere.example.com/") });
const manual = await safeFetch("https://m.example.com/", { method: "HEAD", redirect: "manual" });
ok("manual mode returns the raw 3xx without following", manual?.status === 301 && fetchCalls.length === 1);

// 5. A normal public GET returns the response.
stubFetch({ "https://ok.example.com/": resp(200) });
ok("normal public fetch returns the response", (await safeFetch("https://ok.example.com/", { redirect: "follow" }))?.status === 200);

console.log(`\nSSRF scan guard: ${pass}/${pass + fail} passed`);
if (fail) { console.error("ssrf-scan-guard validation FAILED"); process.exit(1); }
console.log("ssrf-scan-guard validation passed");
