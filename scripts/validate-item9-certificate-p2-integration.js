#!/usr/bin/env node
import { assertProbeFetch } from './lib/probe-contract-fixture.mjs';
// Item 9 P2 — deterministic production-module integration and deadline fixtures.
//
// Exercises the real SSL, live TLS collector client, subdomain discovery and
// certificate-intelligence modules. Network edges are deterministic fixtures; no
// production caller is replaced and no external domain/TLS action occurs.
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { runCertificateIntelligenceModule } from "../workers/scan-api/src/engines/cert-intel.js";
import { attachLiveTlsToSsl, collectLiveTls } from "../workers/scan-api/src/engines/network-probe.js";
import {
  MODULE_SUBREQUEST_COST,
  SCAN_MODULE_BUDGETS,
} from "../workers/scan-api/src/engines/scan-budget.js";
import { runSslModule } from "../workers/scan-api/src/engines/ssl-scan.js";
import { runSubdomainsModule } from "../workers/scan-api/src/engines/subdomains-scan.js";
import { liveTlsProbeBinding } from "./lib/live-tls-fixture.mjs";

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

// The collector binding for each scenario: a served certificate, a refused
// request, or a request that never answers before the scan aborts it.
function collectorFor(mode) {
  if (mode === "observed") {
    return liveTlsProbeBinding({
      days: 98,
      issuer: "CN=Fixture Current CA",
      dnsNames: ["example.com", "api.example.com", "*.example.com"],
    });
  }
  const calls = [];
  return {
    calls,
    fetch: (_url, init) => {
      calls.push(assertProbeFetch(init));
      if (mode === "unavailable") return Promise.reject(new TypeError("collector refused"));
      return new Promise(() => {});
    },
  };
}

async function runScenario(scenario) {
  const sslAccounting = accounting(fixture.module_subrequest_cap);
  const subdomainAccounting = accounting(MODULE_SUBREQUEST_COST.subdomains);
  const collector = collectorFor(scenario.collector);
  const controller = new AbortController();
  if (scenario.collector === "timeout") setTimeout(() => controller.abort("deadline"), 5);
  const started = realDateNow();
  const [sslHttp, subdomains, liveTls] = await Promise.all([
    runSslModule("example.com", {
      accounting: sslAccounting,
      now: () => Date.parse(NOW),
    }),
    runSubdomainsModule("example.com", {
      accounting: subdomainAccounting,
      cache: new Map(),
    }),
    collectLiveTls({ NETWORK_PROBE: collector }, {
      domain: "example.com",
      scanId: "scan-item9-p2",
      workspaceId: "ws-item9-p2",
      requestId: "probe-item9-p2",
      signal: controller.signal,
    }),
  ]);
  const elapsedMs = realDateNow() - started;
  const ssl = attachLiveTlsToSsl(sslHttp, liveTls);
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
      observedAt: NOW,
      engineVersion: "item9-p2-fixture",
    },
  );
  return {
    collector,
    elapsedMs,
    sslAccounting,
    subdomainAccounting,
    ssl,
    subdomains,
    intelligence,
  };
}

Date.now = () => Date.parse(NOW);
Math.random = () => 0.123456789;
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
    eq(`${prefix}: the live TLS collector is asked exactly once`,
      result.collector.calls.length, 1);
    ok(`${prefix}: SSL and subdomains carry no external certificate-log source`,
      !("ct_sources" in result.ssl) && !("sources" in result.subdomains) &&
        result.subdomains.source === "dns_discovery",
      JSON.stringify({ ssl: Object.keys(result.ssl), subdomains: result.subdomains.source }));
    ok(`${prefix}: executable deadline stays inside 9 seconds`,
      result.elapsedMs < fixture.module_budget_ms,
      `elapsed ${result.elapsedMs}ms`);
    ok(`${prefix}: SSL stays within six subrequests`,
      result.sslAccounting.counters.attempts <= fixture.module_subrequest_cap,
      `attempts ${result.sslAccounting.counters.attempts}`);
    eq(`${prefix}: SSL states why the live leaf is missing`,
      result.ssl.incomplete_reason ?? null,
      scenario.expected_ssl_incomplete_reason);
    eq(`${prefix}: live leaf completeness`,
      signals.leaf.completeness_state,
      scenario.expected_leaf_state);
    eq(`${prefix}: issuer completeness`,
      signals.issuer.completeness_state,
      scenario.expected_issuer_state);
    eq(`${prefix}: independently reliable active-service state survives`,
      signals.active_service.completeness_state,
      scenario.expected_active_service_state);
    eq(`${prefix}: independently reliable active-service observation survives`,
      signals.active_service.observation,
      scenario.expected_active_service_observation);
    eq(`${prefix}: a leaf without a presented chain never claims a chain`,
      signals.chain.observation, "unknown");
    eq(`${prefix}: historical multiplicity never promotes parallel set`,
      signals.parallel_certificate_set.observation, "unknown");
    eq(`${prefix}: parallel collection remains explicitly unperformed`,
      result.ssl.certificate_evidence.parallel_certificate_set.collection_performed,
      false);
    eq(`${prefix}: a missing leaf never fabricates a no-HTTPS alert`,
      result.intelligence.suspicious_certificate_signals
        .some((signal) => signal.signal === "no_https"),
      false);
  }

  const complete = results.get("complete");
  eq("complete: the issuer is the served certificate's issuer",
    complete.intelligence.issuer, "CN=Fixture Current CA");
  eq("complete: certificate intelligence is attributed to the live leaf",
    complete.intelligence.evidence_source, "live_tls");
  eq("complete: expiry is measured from the collector observation",
    complete.intelligence.days_until_expiry, 98);
  // Without a captured leaf the certificate is honestly not observed, and the
  // reason is the collector's, never a guess from another source.
  for (const name of ["collector-unavailable", "collector-timeout"]) {
    const { intelligence, subdomains } = results.get(name);
    ok(`${name}: certificate intelligence is incomplete, not healthy`,
      intelligence.incomplete === true &&
        intelligence.evidence_source === "not_observed" &&
        intelligence.live_certificate_verified === false,
      JSON.stringify({ incomplete: intelligence.incomplete, reason: intelligence.incomplete_reason }));
    ok(`${name}: subdomain discovery is unaffected by the collector`,
      subdomains.incomplete !== true && subdomains.source === "dns_discovery",
      JSON.stringify(subdomains));
  }

  const serviceUnexecuted = runCertificateIntelligenceModule(
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
      observedAt: NOW,
      engineVersion: "item9-p2-fixture",
    },
  );
  eq("the live leaf issuer stays observed when the HTTP probe did not run",
    serviceUnexecuted.signal_completeness.signals.issuer.observation, "present");
  eq("an unexecuted HTTP probe never upgrades active-service",
    serviceUnexecuted.signal_completeness.signals.active_service.observation, "unknown");
  eq("an unexecuted service probe never fabricates no-HTTPS",
    serviceUnexecuted.suspicious_certificate_signals
      .some((signal) => signal.signal === "no_https"),
    false);

  const serviceAbsent = runCertificateIntelligenceModule(
    {
      ssl: {
        ...complete.ssl,
        tls_state: "positively_absent",
        https_probe_executed: true,
        https_available: false,
        certificate_evidence: { ...(complete.ssl.certificate_evidence ?? {}), observed_at: NOW },
        tls_positive_absence_evidence: {
          state: "positively_absent", execution: "completed",
          source_type: "approved_active_tls_collector",
          collector: "item9_contract_fixture", collector_version: "1",
          endpoint: "https://example.com", assessed_domain: "example.com", observed_at: NOW,
          absence_outcome: "tls_service_absent", evidence_grade: "positive_absence",
        },
      },
      subdomains: complete.subdomains,
    },
    "example.com",
    {
      observedAt: NOW,
      engineVersion: "item9-p2-fixture",
    },
  );
  eq("observed service absence is scoped to active-service",
    serviceAbsent.signal_completeness.signals.active_service.observation,
    "absent");
  eq("observed service absence does not erase the live leaf issuer",
    serviceAbsent.signal_completeness.signals.issuer.observation, "present");
} finally {
  Date.now = realDateNow;
  globalThis.fetch = realFetch;
  Math.random = realRandom;
}

console.log(`\nItem 9 P2 integration fixtures: ${pass} passed, ${fail} failed`);
if (!fail) console.log("Item 9 P2 integration fixtures passed");
process.exit(fail ? 1 : 0);
