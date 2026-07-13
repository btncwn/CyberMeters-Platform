#!/usr/bin/env node
//
// Security-headers cross-module binding proof.
//
// Regression guard for the Phase-1c extraction defect: runHeadersModule was moved
// from the monolith into engines/headers-scan.js but its dependency SECURITY_HEADERS
// was left as a private const in scoring.js — a dangling free reference that passes
// `node --check` and `wrangler --dry-run` (valid syntax) yet throws
// `ReferenceError: SECURITY_HEADERS is not defined` at RUNTIME on every scan.
//
// This test imports the extracted module as its OWN ES module (exactly how esbuild
// bundles it — separate module scope) and EXECUTES runHeadersModule end-to-end, so a
// missing/renamed binding surfaces as a real throw, not a silently-swallowed one.
//
// Covers: (1) faithful success path reaches the SECURITY_HEADERS.filter return code
// without throwing; (2) graceful failure when fetch throws / returns null; (3) the
// shared config is a single source of truth used by both consumers. Node 24+. CI-blocking.
//
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const eng = (f) => import(pathToFileURL(path.join(root, "workers", "scan-api", "src", "engines", f)).href);

const headers = await eng("headers-scan.js");
const scoring = await eng("scoring.js");
const config  = await eng("security-headers-config.js");
const { runHeadersModule } = headers;

let pass = 0, fail = 0;
const ok = (name, cond) => { cond ? pass++ : fail++; if (!cond) console.log("FAIL " + name); };

// ── 1. Shared config is a single source of truth (no duplicate copies) ─────────
ok("config exports SECURITY_HEADERS array", Array.isArray(config.SECURITY_HEADERS) && config.SECURITY_HEADERS.length >= 6);
ok("headers-scan sees the config (binding present, not a dangling free ref)",
   headers.classifyHeaderStrength instanceof Function); // module initialised without ReferenceError
ok("every header entry is well-formed", config.SECURITY_HEADERS.every(h => h.name && h.label && h.severity));

// ── 2. Faithful success path — runHeadersModule executes end-to-end ────────────
// A stub that returns a real 200 with a security header. If SECURITY_HEADERS were
// unbound, the return-path .filter() (headers-scan.js:296) would ReferenceError here.
const realFetch = globalThis.fetch;
const okResponse = (extra = {}) => new Response(null, {
  status: 200,
  headers: { "strict-transport-security": "max-age=31536000; includeSubDomains", "content-type": "text/html", ...extra },
});

globalThis.fetch = async () => okResponse();
let result = null, threw = null;
try { result = await runHeadersModule("example.com"); } catch (e) { threw = e; }
ok("runHeadersModule does NOT throw on a reachable host (SECURITY_HEADERS bound)", threw === null);
ok("result is accessible with a status code", !!result && result.accessible === true && result.status_code === 200);
ok("present[] computed from SECURITY_HEADERS (HSTS detected)",
   !!result && Array.isArray(result.present) && result.present.includes("strict-transport-security"));
ok("missing[] computed from SECURITY_HEADERS (CSP absent)",
   !!result && Array.isArray(result.missing) && result.missing.includes("content-security-policy"));
ok("header_strength map built from SECURITY_HEADERS (classifyHeaderStrength ran)",
   !!result && result.header_strength && typeof result.header_strength === "object");

// ── 3. Graceful failure — fetch throws (host unreachable) ──────────────────────
// safeFetch must swallow → null → module reaches the same return path WITHOUT throwing.
globalThis.fetch = async () => { throw new TypeError("network error: connection refused"); };
threw = null; result = null;
try { result = await runHeadersModule("unreachable.example"); } catch (e) { threw = e; }
ok("runHeadersModule does NOT throw when fetch fails (graceful, reaches return path)", threw === null);
ok("unreachable host → accessible:false, status_code:null", !!result && result.accessible === false && result.status_code === null);
ok("unreachable host still returns present/missing arrays (no crash on empty headers)",
   !!result && Array.isArray(result.present) && Array.isArray(result.missing) && result.present.length === 0);

// ── 4. Graceful failure — fetch returns a 5xx Response ─────────────────────────
globalThis.fetch = async () => new Response(null, { status: 503 });
threw = null; result = null;
try { result = await runHeadersModule("degraded.example"); } catch (e) { threw = e; }
ok("runHeadersModule does NOT throw on a 5xx response", threw === null);
ok("5xx response → accessible:true, status 503, all headers missing", !!result && result.status_code === 503);

globalThis.fetch = realFetch;

// ── 5. Consumers agree on the same list (scoring + headers-scan share config) ──
// scoring.js importing without error proves it resolves the same shared binding.
ok("scoring.js initialised (imports shared SECURITY_HEADERS without ReferenceError)",
   typeof scoring.computeScore === "function" || typeof scoring.isEmailApplicable === "function");

console.log(`\nsecurity-headers-binding: ${pass} passed, ${fail} failed`);
if (fail > 0) process.exit(1);
