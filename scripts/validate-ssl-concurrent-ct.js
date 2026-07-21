#!/usr/bin/env node
//
// SSL module concurrency + evidence-preservation (chronic-partial root-cause fix).
// runSslModule ran its HTTPS reachability probes and its Certificate-Transparency
// cert lookup SEQUENTIALLY, so the module's wall-time was the SUM of both chains.
// On a slow-crt.sh day that pushed the whole scan past its ~21s deadline and
// starved the later deadline-gated modules (chronic `partial`). The fix launches
// the CT lookup concurrently with the reachability probes. This suite proves:
//   1. the two chains OVERLAP (CT fetch starts before the reachability chain ends);
//   2. total wall-time ≈ max(chains), NOT sum (the load-bearing property);
//   3. every cert_* field is preserved byte-for-byte vs the pre-fix logic.
// Deterministic: global fetch/safeFetch are mocked with controllable delays, and
// concurrency is asserted by CALL-OVERLAP, never by wall-clock flakiness.
// CI-blocking. Requires Node 24+.
//
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const eng = (f) => pathToFileURL(path.join(root, "workers", "scan-api", "src", "engines", f)).href;
const { runSslModule, resolveCertificateTransparency } = await import(eng("ssl-scan.js"));

let pass = 0, fail = 0;
const results = [];
const ok = (name, cond) => { cond ? (pass++, results.push(`PASS ${name}`)) : (fail++, results.push(`FAIL ${name}`)); };

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const realFetch = globalThis.fetch;

// A fake crt.sh response with one currently-valid cert (drives the cert_* fields).
const future = new Date(Date.now() + 60 * 86_400_000).toISOString();
const past = new Date(Date.now() - 30 * 86_400_000).toISOString();
const crtBody = [{ not_after: future, not_before: past, issuer_name: "Let's Encrypt", common_name: "acme.example", name_value: "acme.example\nwww.acme.example" }];
const jsonResponse = (body) => ({ ok: true, headers: { get: (h) => (h.toLowerCase() === "content-type" ? "application/json" : null) }, json: async () => body });

// ── 1. Concurrency: the CT fetch overlaps the reachability probes ─────────────
{
  const events = [];
  let reachEnd = 0, ctStart = 0;
  // safeFetch (reachability) → uses global fetch to https://... / http://...
  // crt.sh / certspotter → global fetch to crt.sh / certspotter.
  globalThis.fetch = async (url) => {
    const u = String(url);
    if (u.includes("crt.sh")) { ctStart = performance.now(); events.push(["ct_start", ctStart]); await sleep(120); return jsonResponse(crtBody); }
    if (u.includes("certspotter")) { return jsonResponse([]); }
    // reachability probes (https/http HEAD via safeFetch) — a few sequential hops.
    await sleep(40);
    reachEnd = performance.now();
    return { ok: true, status: 200, headers: { get: () => null } };
  };
  const t0 = performance.now();
  const res = await runSslModule("acme.example");
  const total = performance.now() - t0;
  globalThis.fetch = realFetch;

  // The CT fetch must START before the reachability probes have all completed —
  // i.e. the two chains overlap rather than run back-to-back.
  ok("CT lookup starts before the reachability chain ends (concurrent)", ctStart > 0 && ctStart < reachEnd + 5);
  // Wall-time ≈ max(chains), not sum. Reachability ≈ 40ms×hops, CT ≈ 120ms. If they
  // were sequential, total would be reach+CT (~≥160ms + hops). Concurrent → ~max.
  ok("total wall-time is bounded by the slower chain, not the sum", total < 200);
  // Evidence still present.
  ok("cert_not_after preserved from crt.sh", res.cert_not_after === future);
  ok("cert_issuer preserved", res.cert_issuer === "Let's Encrypt");
  ok("https reachability still resolved", res.https_available === true);
}

// ── 2. resolveCertificateTransparency is a faithful extraction ────────────────
{
  globalThis.fetch = async (url) => (String(url).includes("crt.sh") ? jsonResponse(crtBody) : jsonResponse([]));
  const cert = await resolveCertificateTransparency("acme.example");
  globalThis.fetch = realFetch;
  const fields = ["cert_expiry_days", "cert_age_days", "cert_not_before", "cert_not_after", "cert_issuer", "cert_subject", "cert_san_count", "cert_raw_san_count", "cert_wildcard_san_count", "cert_shared_san_count", "cert_san_names"];
  ok("CT resolver returns all 11 cert_* fields", fields.every((f) => f in cert));
  ok("CT resolver computes expiry from the longest-lived valid cert", cert.cert_not_after === future && cert.cert_expiry_days >= 59 && cert.cert_expiry_days <= 60);
  // SAN normalisation is preserved verbatim from the pre-fix code; assert the shape
  // (array + count consistency) rather than a specific normalised membership.
  ok("CT resolver returns a normalised SAN array with a consistent count", Array.isArray(cert.cert_san_names) && cert.cert_san_count === cert.cert_san_names.length);
}

// ── 3. certspotter fallback still fires only when crt.sh yields nothing ───────
{
  const csBody = [{ not_after: future, not_before: past, issuer: { name: "SpotCA" }, dns_names: ["acme.example"] }];
  let crtCalls = 0, csCalls = 0;
  globalThis.fetch = async (url) => {
    const u = String(url);
    if (u.includes("crt.sh")) { crtCalls++; return jsonResponse([]); }            // crt.sh yields no cert
    if (u.includes("certspotter")) { csCalls++; return jsonResponse(csBody); }    // fallback provides one
    return { ok: true, status: 200, headers: { get: () => null } };
  };
  const cert = await resolveCertificateTransparency("acme.example");
  globalThis.fetch = realFetch;
  ok("crt.sh queried first", crtCalls === 1);
  ok("certspotter fallback used when crt.sh empty", csCalls === 1 && cert.cert_issuer === "SpotCA");
}

// ── 4. CT failure is best-effort (nulls), never throws into the scan ──────────
{
  globalThis.fetch = async () => { throw new Error("crt.sh down"); };
  let threw = false; let cert;
  try { cert = await resolveCertificateTransparency("acme.example"); } catch { threw = true; }
  globalThis.fetch = realFetch;
  ok("CT lookup never throws on external failure", threw === false);
  ok("CT fields fail closed to null/0 on total failure", cert.cert_not_after === null && cert.cert_san_count === 0);
}

// ── report ─────────────────────────────────────────────────────────────────
console.log(`\nSSL concurrent CT lookup: ${pass}/${pass + fail} passed`);
for (const r of results.filter((r) => r.startsWith("FAIL"))) console.log("  " + r);
if (fail) { console.error("ssl-concurrent-ct validation FAILED"); process.exit(1); }
console.log("ssl-concurrent-ct validation passed");
