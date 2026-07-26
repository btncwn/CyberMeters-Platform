#!/usr/bin/env node
// Item 9 P2 — deterministic production-module integration and deadline fixtures.
//
// Exercises the real SSL, shared CT cache, subdomain and certificate-intelligence
// modules. Network edges are deterministic fixtures; no production caller is
// replaced and no external domain/CT/TLS action occurs.
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { runCertificateIntelligenceModule } from "../workers/scan-api/src/engines/cert-intel.js";
import {
  createCertificateTransparencyCache,
  CT_PROVIDER_POLICIES,
} from "../workers/scan-api/src/engines/ct-provider-cache.js";
import {
  MODULE_SUBREQUEST_COST,
  SCAN_MODULE_BUDGETS,
} from "../workers/scan-api/src/engines/scan-budget.js";
import { runSslModule } from "../workers/scan-api/src/engines/ssl-scan.js";
import { runSubdomainsModule } from "../workers/scan-api/src/engines/subdomains-scan.js";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const fixture = JSON.parse(fs.readFileSync(path.join(
  root,
  "scripts",
  "fixtures",
  "item9-p2-certificate-deadlines.json",
), "utf8"));
const NOW = "2026-07-26T12:00:00.000Z";
const realDateNow = Date.now;
const realFetch = globalThis.fetch;
const realRandom = Math.random;
const realConsoleError = console.error;
let pass = 0;
let fail = 0;

const ok = (name, condition, detail = "") => {
  condition ? pass += 1 : fail += 1;
  if (!condition) console.error(`FAIL ${name}${detail ? ` — ${detail}` : ""}`);
};
const eq = (name, got, want) =>
  ok(name, got === want,
    `got ${JSON.stringify(got)} want ${JSON.stringify(want)}`);

const jsonResponse = (body, status = 200) => new Response(JSON.stringify(body), {
  status,
  headers: { "content-type": "application/json" },
});

const crtCertificates = [
  {
    id: "crt-current",
    not_before: "2026-07-01T00:00:00.000Z",
    not_after: "2026-10-01T00:00:00.000Z",
    issuer_name: "Fixture Current CA",
    common_name: "example.com",
    name_value: "example.com\nwww.example.com\n*.example.com",
  },
  {
    id: "crt-historical",
    not_before: "2026-01-01T00:00:00.000Z",
    not_after: "2026-08-01T00:00:00.000Z",
    issuer_name: "Fixture Historical CA",
    common_name: "example.com",
    name_value: "example.com\nold.example.com",
  },
];
const certSpotterCertificates = [{
  id: "spot-current",
  not_before: "2026-07-02T00:00:00.000Z",
  not_after: "2026-11-01T00:00:00.000Z",
  issuer: { name: "Fixture Fallback CA" },
  dns_names: ["example.com", "api.example.com", "*.example.com"],
}];

function accounting(limit) {
  const counters = { attempts: 0, completed: 0, errors: 0 };
  return {
    counters,
    remainingMs: () => fixture.module_budget_ms,
    assertCanIssue() {
      if (counters.attempts >= limit) {
        throw new DOMException("module subrequest cap exhausted", "AbortError");
      }
    },
    recordAttempt() { counters.attempts += 1; },
    recordCompleted() { counters.completed += 1; },
    recordError() { counters.errors += 1; },
  };
}

function timeoutSignal(ms) {
  const controller = new AbortController();
  setTimeout(
    () => controller.abort(new DOMException("provider timed out", "TimeoutError")),
    Math.min(ms, 5),
  );
  return controller.signal;
}

function providerFixture(mode, calls) {
  return async (input, { signal } = {}) => {
    const url = String(input);
    const provider = url.includes("crt.sh") ? "crt_sh" : "certspotter";
    calls[provider] += 1;
    const outcome = mode[provider];
    if (outcome === "timeout") {
      return new Promise((_resolve, reject) => {
        signal?.addEventListener(
          "abort",
          () => reject(signal.reason),
          { once: true },
        );
      });
    }
    if (outcome === "unavailable") return jsonResponse({}, 403);
    return jsonResponse(
      provider === "crt_sh" ? crtCertificates : certSpotterCertificates,
    );
  };
}

async function runScenario(scenario) {
  const calls = { crt_sh: 0, certspotter: 0 };
  const sslAccounting = accounting(fixture.module_subrequest_cap);
  const subdomainAccounting = accounting(MODULE_SUBREQUEST_COST.subdomains);
  const policies = {
    ...CT_PROVIDER_POLICIES,
    crt_sh: {
      ...CT_PROVIDER_POLICIES.crt_sh,
      timeoutMs: 5,
      maxAttempts: 1,
      backoffMs: 0,
    },
    certspotter: {
      ...CT_PROVIDER_POLICIES.certspotter,
      timeoutMs: 5,
      maxAttempts: 1,
      backoffMs: 0,
    },
  };
  const cache = createCertificateTransparencyCache({
    fetcher: providerFixture(scenario, calls),
    policies,
    remainingMs: () => fixture.module_budget_ms,
    now: realDateNow,
    timeoutSignal,
  });
  const started = realDateNow();
  const [ssl, subdomains] = await Promise.all([
    runSslModule("example.com", {
      accounting: sslAccounting,
      ctCache: cache,
      now: () => Date.parse(NOW),
    }),
    runSubdomainsModule("example.com", {
      accounting: subdomainAccounting,
      ctCache: cache,
    }),
  ]);
  const elapsedMs = realDateNow() - started;
  const providerHealth = cache.healthSnapshot();
  const modules = {
    ssl,
    subdomains,
    // Historical output is intentionally present. The production adapter must
    // ignore it when deriving simultaneous live endpoint multiplicity.
    certificate_intelligence: {
      parallel_evidence_complete: true,
      historical_certificates: ["old", "current"],
    },
  };
  const intelligence = runCertificateIntelligenceModule(
    modules,
    "example.com",
    {
      providerHealth,
      observedAt: NOW,
      engineVersion: "item9-p2-fixture",
    },
  );
  return {
    calls,
    elapsedMs,
    sslAccounting,
    subdomainAccounting,
    ssl,
    subdomains,
    providerHealth,
    intelligence,
  };
}

Date.now = () => Date.parse(NOW);
Math.random = () => 0.123456789;
console.error = (...args) => {
  if (!String(args[0] || "").startsWith("[scan/ct/")) {
    realConsoleError(...args);
  }
};
globalThis.fetch = async (input) => {
  const url = new URL(String(input));
  if (url.hostname === "cloudflare-dns.com" || url.hostname === "dns.google") {
    return jsonResponse({ Status: 0, Answer: [] });
  }
  return new Response("", {
    status: 200,
    headers: { "content-type": "text/html" },
  });
};

try {
  eq("fixture pins SSL module budget", fixture.module_budget_ms, 9_000);
  eq("production SSL module budget stays 9 seconds",
    SCAN_MODULE_BUDGETS.ssl, fixture.module_budget_ms);
  eq("fixture pins SSL subrequest cap", fixture.module_subrequest_cap, 6);
  eq("production SSL subrequest cost stays 6",
    MODULE_SUBREQUEST_COST.ssl, fixture.module_subrequest_cap);

  const results = new Map();
  for (const scenario of fixture.scenarios) {
    const result = await runScenario(scenario);
    results.set(scenario.name, result);
    const signals = result.intelligence.signal_completeness.signals;
    const prefix = scenario.name;

    eq(`${prefix}: P1 model is attached in the production certificate engine`,
      result.intelligence.signal_completeness.model_version,
      fixture.model_version);
    eq(`${prefix}: one shared crt.sh logical lookup`,
      result.calls.crt_sh, 1);
    eq(`${prefix}: one shared CertSpotter logical lookup`,
      result.calls.certspotter, 1);
    ok(`${prefix}: executable deadline stays inside 9 seconds`,
      result.elapsedMs < fixture.module_budget_ms,
      `elapsed ${result.elapsedMs}ms`);
    ok(`${prefix}: SSL stays within six subrequests`,
      result.sslAccounting.counters.attempts <= fixture.module_subrequest_cap,
      `attempts ${result.sslAccounting.counters.attempts}`);
    eq(`${prefix}: CT completeness`,
      signals.certificate_transparency.completeness_state,
      scenario.expected_ct_state);
    eq(`${prefix}: issuer completeness`,
      signals.issuer.completeness_state,
      scenario.expected_issuer_state);
    eq(`${prefix}: independently reliable active-service state survives`,
      signals.active_service.completeness_state,
      scenario.expected_active_service_state);
    eq(`${prefix}: independently reliable active-service observation survives`,
      signals.active_service.observation,
      scenario.expected_active_service_observation);
    eq(`${prefix}: CT never promotes live leaf`,
      signals.leaf.observation, "unknown");
    eq(`${prefix}: CT never promotes live chain`,
      signals.chain.observation, "unknown");
    eq(`${prefix}: CT/historical multiplicity never promotes parallel set`,
      signals.parallel_certificate_set.observation, "unknown");
    eq(`${prefix}: parallel collection remains explicitly unperformed`,
      result.ssl.certificate_evidence.parallel_certificate_set.collection_performed,
      false);
    eq(`${prefix}: incomplete CT never fabricates a no-HTTPS alert`,
      result.intelligence.suspicious_certificate_signals
        .some((signal) => signal.signal === "no_https"),
      false);
  }

  const complete = results.get("complete");
  const ctOnly = runCertificateIntelligenceModule(
    {
      ssl: {
        ...complete.ssl,
        https_probe_executed: false,
        https_available: null,
      },
      subdomains: complete.subdomains,
    },
    "example.com",
    {
      providerHealth: complete.providerHealth,
      observedAt: NOW,
      engineVersion: "item9-p2-fixture",
    },
  );
  eq("CT-only issuer remains an issuance observation",
    ctOnly.signal_completeness.signals.issuer.observation, "present");
  eq("CT-only data never upgrades active-service",
    ctOnly.signal_completeness.signals.active_service.observation, "unknown");
  eq("CT-only data never upgrades leaf",
    ctOnly.signal_completeness.signals.leaf.observation, "unknown");
  eq("an unexecuted service probe never fabricates no-HTTPS",
    ctOnly.suspicious_certificate_signals
      .some((signal) => signal.signal === "no_https"),
    false);

  const serviceAbsent = runCertificateIntelligenceModule(
    {
      ssl: {
        ...complete.ssl,
        https_probe_executed: true,
        https_available: false,
      },
      subdomains: complete.subdomains,
    },
    "example.com",
    {
      providerHealth: complete.providerHealth,
      observedAt: NOW,
      engineVersion: "item9-p2-fixture",
    },
  );
  eq("observed service absence is scoped to active-service",
    serviceAbsent.signal_completeness.signals.active_service.observation,
    "absent");
  eq("observed service absence does not erase CT issuer",
    serviceAbsent.signal_completeness.signals.issuer.observation, "present");
} finally {
  Date.now = realDateNow;
  globalThis.fetch = realFetch;
  Math.random = realRandom;
  console.error = realConsoleError;
}

console.log(`\nItem 9 P2 integration fixtures: ${pass} passed, ${fail} failed`);
if (!fail) console.log("Item 9 P2 integration fixtures passed");
process.exit(fail ? 1 : 0);
