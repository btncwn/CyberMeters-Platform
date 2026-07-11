#!/usr/bin/env node
//
// Simple dependency-free concurrent-load driver (native fetch). Fires a fixed
// number of concurrent requests at a target endpoint for a duration and reports
// throughput, latency percentiles, and error/rate-limit rates — enough to spot a
// bottleneck or confirm the global rate limiter bites, without pulling in k6.
//
// Usage:
//   TARGET=https://cybermeters-platform.ttrnn47.workers.dev/health \
//   CONCURRENCY=50 DURATION_S=15 node scripts/load/concurrent-requests.js
//
// To exercise an authenticated / write path, set METHOD, PATH_BODY, and TOKEN.
// Default target is /health (safe, unauthenticated) so an accidental run is inert.
//
const TARGET = process.env.TARGET || "https://cybermeters-platform.ttrnn47.workers.dev/health";
const CONCURRENCY = Number(process.env.CONCURRENCY || 50);
const DURATION_S = Number(process.env.DURATION_S || 15);
const METHOD = process.env.METHOD || "GET";
const TOKEN = process.env.TOKEN || "";
const BODY = process.env.PATH_BODY || "";

const headers = { "Content-Type": "application/json", ...(TOKEN ? { Authorization: `Bearer ${TOKEN}` } : {}) };
const deadline = Date.now() + DURATION_S * 1000;
const latencies = [];
let ok = 0, rateLimited = 0, errors = 0, total = 0;

async function worker() {
  while (Date.now() < deadline) {
    const t0 = performance.now();
    try {
      const res = await fetch(TARGET, { method: METHOD, headers, body: METHOD === "GET" ? undefined : BODY });
      latencies.push(performance.now() - t0);
      total++;
      if (res.status === 429) rateLimited++;
      else if (res.ok || res.status === 401) ok++; // 401 = reached the app, auth enforced
      else errors++;
    } catch { errors++; total++; }
  }
}

const pct = (arr, p) => { if (!arr.length) return 0; const s = [...arr].sort((a, b) => a - b); return s[Math.min(s.length - 1, Math.floor((p / 100) * s.length))]; };

console.log(`Load: ${CONCURRENCY} workers × ${DURATION_S}s → ${METHOD} ${TARGET}`);
const started = Date.now();
await Promise.all(Array.from({ length: CONCURRENCY }, worker));
const elapsed = (Date.now() - started) / 1000;

console.log(`\ntotal        : ${total} (${(total / elapsed).toFixed(1)} req/s)`);
console.log(`ok/reached   : ${ok}`);
console.log(`rate-limited : ${rateLimited} (429)`);
console.log(`errors       : ${errors}`);
console.log(`latency p50  : ${pct(latencies, 50).toFixed(0)} ms`);
console.log(`latency p95  : ${pct(latencies, 95).toFixed(0)} ms`);
console.log(`latency p99  : ${pct(latencies, 99).toFixed(0)} ms`);
console.log(`latency max  : ${Math.max(0, ...latencies).toFixed(0)} ms`);
