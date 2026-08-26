#!/usr/bin/env node
//
// AS-B6 reserved-mode deadline/cancellation closure.
//
// Proves three load-bearing laws against production modules:
//   1. the dormant reserved branch arms the canonical global deadline;
//   2. every physical reserved context loses launch authority on abort, while an
//      already-issued SSRF-safe GET receives the same signal;
//   3. a scan entered after the deadline emits honest incomplete/not-assessed
//      shapes and launches zero external requests.

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const repoRoot = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const targetRoot = process.env.ASB6_RESERVED_TARGET_ROOT || repoRoot;
const engineRoot = path.join(targetRoot, "workers", "scan-api", "src", "engines");
const load = (file) => import(pathToFileURL(path.join(engineRoot, file)).href);
const platformAbortWording =
  "CyberMeters did not observe the provider result within the scan's global execution window.";

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

const scanBudgetSource = fs.readFileSync(path.join(engineRoot, "scan-budget.js"), "utf8");
const reservedProbeSource = fs.readFileSync(path.join(engineRoot, "reserved-probe.js"), "utf8");
const scanEngineSource = fs.readFileSync(path.join(engineRoot, "scan-engine.js"), "utf8");

ok(
  "ASB6R_ENGINE_WIRES_DEADLINE_ARM",
  /const reservedMode = capacity\.mode === "reserved";\s*if \(reservedMode\) deadline\.arm\(\);/.test(scanEngineSource)
    && /finally \{\s*deadline\.disarm\?\.\(\);\s*\}/.test(scanEngineSource)
    && !/not be treated as[\s\S]{0,120}B2 cancellation\/accounting guarantees/.test(scanEngineSource),
);
ok(
  "ASB6R_PHYSICAL_CONTEXT_BINDS_SIGNAL",
  /assertCanIssue: \(\) => \{ assertNotCancelled\(\)/.test(scanBudgetSource)
    && /recordAttempt: \(\) => \{ assertNotCancelled\(\)/.test(scanBudgetSource),
);
ok(
  "ASB6R_RESERVED_GET_COMBINES_DEADLINE_SIGNAL",
  /combineSignals\(opts\?\.signal, activeAccounting\?\.signal, AbortSignal\.timeout\(timeoutMs\)\)/.test(reservedProbeSource),
);

if (process.env.ASB6_RESERVED_RED_FIRST_ONLY === "1") {
  console.log(`\nAS-B6 reserved deadline red-first: ${passed} passed, ${failed} failed`);
  if (failed > 0) process.exit(1);
  process.exit(0);
}

const budgetModule = await load("scan-budget.js");
const reservedProbeModule = await load("reserved-probe.js");
const reservedModule = await load("reserved-scan.js");
const {
  PhysicalSubrequestCounter,
  createScanDeadline,
  resolveScanCapacity,
} = budgetModule;
const { makeSsrfSafeProbeFetch } = reservedProbeModule;
const { runReservedScan } = reservedModule;

// Deterministic timer ownership: inject the timer and fire it ourselves.
let timerCallback = null;
const timerDeadline = createScanDeadline({ SCAN_DEADLINE_MS: 5_000 }, () => 1_000);
const timerArmed = typeof timerDeadline.arm === "function" && timerDeadline.arm({
  setTimer(callback) { timerCallback = callback; return { unref() {} }; },
  clearTimer() {},
});
timerCallback?.();
ok(
  "ASB6R_DEADLINE_TIMER_ARMS_AND_ABORTS",
  timerArmed === true
    && typeof timerCallback === "function"
    && timerDeadline.signal.aborted === true
    && timerDeadline.globalDeadlineProvenance().reason === "scan_deadline_exhausted",
);

// An already-issued reserved GET must receive the deadline signal. A later GET
// must be refused at the physical boundary before global fetch is called.
const realFetch = globalThis.fetch;
const liveDeadline = createScanDeadline({ SCAN_DEADLINE_MS: 5_000 }, () => 1_000);
const physical = new PhysicalSubrequestCounter({ limit: 50, safetyMargin: 5 });
const accounting = physical.contextFor("asset_exposure", { signal: liveDeadline.signal });
let fetchCalls = 0;
let fetchSawAbort = false;
globalThis.fetch = async (_url, init = {}) => {
  fetchCalls += 1;
  return new Promise((resolve, reject) => {
    const abort = () => {
      fetchSawAbort = true;
      reject(new DOMException("deadline", "AbortError"));
    };
    if (init.signal?.aborted) abort();
    else init.signal?.addEventListener?.("abort", abort, { once: true });
  });
};
const fetcher = makeSsrfSafeProbeFetch({
  resolver: async () => ({ Answer: [{ data: "93.184.216.34" }] }),
  accounting,
  timeoutMs: 60_000,
});
let inFlightError = null;
let inFlightSettled = false;
const inFlight = fetcher("https://example.com").catch((error) => {
  inFlightError = error;
  return null;
}).finally(() => { inFlightSettled = true; });
for (let i = 0; i < 8 && fetchCalls === 0; i += 1) await Promise.resolve();
liveDeadline.cancel("scan_deadline_exhausted");
for (let i = 0; i < 8 && !inFlightSettled; i += 1) await Promise.resolve();
if (inFlightSettled) await inFlight;
ok(
  "ASB6R_SIGNAL_REMOVAL_INFLIGHT_GET_ABORTED",
  inFlightSettled && fetchCalls === 1 && fetchSawAbort && inFlightError?.name === "AbortError",
  `settled=${inFlightSettled} fetchCalls=${fetchCalls} abort=${fetchSawAbort} error=${inFlightError?.name || null}`,
);
ok(
  "ASB6R_ACCOUNTING_REMOVAL_GET_COUNTED",
  physical.issued === 1 && physical.byCategory.asset_exposure === 1,
  JSON.stringify(physical.snapshot()),
);
let lateError = null;
try {
  await fetcher("https://example.com/late");
} catch (error) {
  lateError = error;
}
ok(
  "ASB6R_LATE_WORK_AFTER_DEADLINE_REFUSED",
  fetchCalls === 1
    && physical.issued === 1
    && lateError?.name === "AbortError"
    && lateError?.code === "scan_deadline_exhausted",
  `fetchCalls=${fetchCalls} issued=${physical.issued} error=${lateError?.name}/${lateError?.code}`,
);

// Full constructor proof: a pre-aborted reserved scan may compute/finalise local
// fallback shapes, but it must launch zero network work and cannot publish clean.
let fullFetchCalls = 0;
globalThis.fetch = async () => {
  fullFetchCalls += 1;
  throw new Error("external leaf launched after deadline");
};
const fullController = new AbortController();
fullController.abort({ reason: "scan_deadline_exhausted" });
let fullResult = null;
let fullError = null;
try {
  fullResult = await runReservedScan("example.com", {
    capacity: resolveScanCapacity({ SCAN_CAPACITY_MODE: "reserved" }),
    signal: fullController.signal,
  });
} catch (error) {
  fullError = error;
} finally {
  globalThis.fetch = realFetch;
}
const m = fullResult?.modules || {};
ok(
  "ASB6R_ABORTED_FULL_RESERVED_SCAN_NOT_ASSESSED",
  fullError == null
    && fullFetchCalls === 0
    && fullResult?.physicalBudget?.issued === 0
    && m.dmarc_core?.incomplete_reason === "scan_deadline_exhausted"
    && m.critical_prefix_discovery?.checked === 0
    && m.critical_prefix_discovery?.incomplete_reason === "scan_deadline_exhausted"
    && m.asset_exposure?.incomplete === true
    && m.asset_exposure?.incomplete_reason === "scan_deadline_exhausted"
    && [m.dns, m.ssl, m.headers, m.email_security, m.subdomains,
      m.technology_detection, m.whois_intelligence,
      m.subdomain_takeover, m.dns_bruteforce]
      .every((value) => value?.incomplete === true && value?.outcome === "deadline_exceeded"),
  JSON.stringify({ fullFetchCalls, error: fullError?.message || null, physical: fullResult?.physicalBudget, modules: m }),
);
ok(
  "ASB6R_PREABORT_CT_PLATFORM_WORDING_PRESERVED",
  [
    m.ssl?.ct_sources?.crt_sh,
    m.ssl?.ct_sources?.certspotter,
    m.subdomains?.sources?.crt_sh,
    m.subdomains?.sources?.certspotter,
  ].every((source) => source?.count === 0 && source?.error === platformAbortWording),
  JSON.stringify({ ssl: m.ssl?.ct_sources, subdomains: m.subdomains?.sources }),
);

console.log(`\nAS-B6 reserved deadline safety: ${passed} passed, ${failed} failed`);
if (failed > 0) process.exit(1);
