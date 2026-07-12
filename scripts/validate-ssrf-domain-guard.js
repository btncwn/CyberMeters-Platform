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

let pass = 0, fail = 0;
const ok = (name, cond) => { cond ? pass++ : fail++; if (!cond) console.log("FAIL " + name); };

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

console.log(`\nSSRF domain guard: ${pass}/${pass + fail} passed`);
if (fail) { console.error("ssrf-domain-guard validation FAILED"); process.exit(1); }
console.log("ssrf-domain-guard validation passed");
