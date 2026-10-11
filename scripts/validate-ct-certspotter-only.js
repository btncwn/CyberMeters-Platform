#!/usr/bin/env node
//
// Certificate Transparency policy: CertSpotter is the only CT source.
//
// Proves, by driving the real cache, orchestrator and modules:
//   • product code (Workers and frontend) names no other CT search service, and
//     the scan engine and free preview pass the optional SSLMate key;
//   • the key reaches only api.certspotter.com, and no other host is contacted;
//   • a CertSpotter success is a COMPLETE CT result, a CertSpotter failure is
//     honest total CT loss (never healthy), and an empty answer stays measured;
//   • monitoring state, attack-surface completeness, certificate intelligence
//     and SSL agree with that;
//   • the shared-SAN measurement comes from the issuance's full SAN list and
//     ownership never rests on a subject the issuance does not carry;
//   • stored records are read with the providers THEY recorded, so a historical
//     two-provider record keeps its meaning (a neutral provider name stands in).
// Node 24+.
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const enginePath = (f) => path.join(root, "workers", "scan-api", "src", "engines", f);
const eng = (f) => pathToFileURL(enginePath(f)).href;
const { CT_PROVIDERS, ctProvidersUsed } = await import(eng("ct-providers.js"));
const { createCertificateTransparencyCache } = await import(eng("ct-provider-cache.js"));
const { runSubdomainsModule } = await import(eng("subdomains-scan.js"));
const { resolveCertificateTransparency } = await import(eng("ssl-scan.js"));
const { deriveSignalMonitoringStates } = await import(eng("signal-monitoring-state.js"));
const { deriveAttackSurfaceSignalCompleteness } = await import(eng("attack-surface-signal-completeness.js"));
const { runCertificateIntelligenceModule, buildCertificateOwnershipAssessment, sharedSanMeasured } = await import(eng("cert-intel.js"));
const { subdomainDiscoveryComplete } = await import(eng("asset-inventory.js"));
const { projectCertificateSharedSanForCustomer } = await import(
  pathToFileURL(path.join(root, "workers", "scan-api", "src", "routes", "certificate-shared-san-projection.js")).href);

let pass = 0, fail = 0;
const ok = (n, c, d = "") => { c ? pass++ : fail++; if (!c) console.log(`FAIL ${n}${d ? " — " + d : ""}`); };
const eq = (n, g, w) => ok(n, JSON.stringify(g) === JSON.stringify(w), `got ${JSON.stringify(g)} want ${JSON.stringify(w)}`);

const jsonResponse = (body, status = 200) => new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
const realFetch = globalThis.fetch;
globalThis.fetch = async (url) => String(url).includes("dns-query")
  ? jsonResponse({ Status: 0, Answer: [] })
  : new Response("", { status: 200 });

const NOW = Date.parse("2026-10-11T12:00:00.000Z");
const issuance = (dnsNames) => ({
  not_before: "2026-09-01T00:00:00.000Z", not_after: "2099-12-01T00:00:00.000Z",
  issuer: { name: "Spot CA" }, dns_names: dnsNames,
});
const certSpotterBody = [issuance(["example.com", "www.example.com", "shop.example.com"])];
function recorder({ certspotter = certSpotterBody } = {}) {
  const calls = { certspotter: 0, other: [], auth: [] };
  const fetcher = async (url, init = {}) => {
    const value = String(url);
    if (value.startsWith("https://api.certspotter.com/")) {
      calls.certspotter += 1;
      calls.auth.push(init.headers?.Authorization ?? null);
      if (typeof certspotter === "number") return jsonResponse({}, certspotter);
      return jsonResponse(certspotter);
    }
    calls.other.push({ url: value, auth: init.headers?.Authorization ?? null });
    return jsonResponse([]);
  };
  return { calls, fetcher };
}
const cacheWith = (fetcher, apiKey = null) => createCertificateTransparencyCache({
  fetcher, certspotterApiKey: apiKey,
  policies: { certspotter: { timeoutMs: 2_000, maxAttempts: 1, backoffMs: 0 } },
});

function productFiles(dir) {
  const out = [];
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    if (entry.name === "node_modules" || entry.name.startsWith(".")) continue;
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) out.push(...productFiles(full));
    else if (/\.(m?js|jsx|ts|tsx)$/.test(entry.name)) out.push(full);
  }
  return out;
}

try {
  // ── 1. Policy, product code and wiring ─────────────────────────────────
  eq("CertSpotter is the only CT provider", [...CT_PROVIDERS], ["certspotter"]);
  {
    // Built from parts so this guard does not itself contain the name.
    const retired = new RegExp(["crt", "[._]?", "sh"].join(""), "i");
    const offenders = [
      ...productFiles(path.join(root, "workers")),
      ...productFiles(path.join(root, "frontend", "src")),
    ].filter((file) => retired.test(fs.readFileSync(file, "utf8")));
    eq("no Worker or frontend file names the retired CT search service",
      offenders.map((file) => path.relative(root, file)), []);
    const engine = fs.readFileSync(enginePath("scan-engine.js"), "utf8");
    const billing = fs.readFileSync(path.join(root, "workers/scan-api/src/routes/billing.js"), "utf8");
    const wired = (src) => /createCertificateTransparencyCache\(\{[\s\S]{0,400}certspotterApiKey: env\?\.CERTSPOTTER_API_KEY \|\| null,/.test(src);
    ok("scan engine passes the optional SSLMate key", wired(engine));
    ok("free preview passes the optional SSLMate key", wired(billing));
  }

  // ── 2. Only CertSpotter is contacted; the key reaches only CertSpotter ──
  {
    const { calls, fetcher } = recorder();
    const cache = cacheWith(fetcher, "sslmate-test-key");
    await cache.get("example.com", "certspotter");
    const other = await cache.get("example.com", "another_provider");
    eq("the SSLMate key is sent as a bearer token to CertSpotter", calls.auth, ["Bearer sslmate-test-key"]);
    eq("no other host is contacted", calls.other, []);
    ok("an unknown provider name is refused, never fetched", other.status === "unavailable" && other.data === null);
    eq("the cache declares CertSpotter as its only provider", [...cache.providers], ["certspotter"]);
    const { calls: noKey, fetcher: noKeyFetcher } = recorder();
    await cacheWith(noKeyFetcher).get("example.com", "certspotter");
    eq("without a key no Authorization header is sent", noKey.auth, [null]);
  }

  // ── 3. Subdomains: success complete, failure honest, empty measured ─────
  const result = await runSubdomainsModule("example.com", { ctCache: cacheWith(recorder().fetcher, "k"), cache: new Map() });
  const failed = await runSubdomainsModule("example.com", { ctCache: cacheWith(recorder({ certspotter: 503 }).fetcher), cache: new Map() });
  {
    eq("discovery reports CertSpotter only", Object.keys(result.sources), ["certspotter"]);
    eq("the result declares its provider set", result.ct_providers, ["certspotter"]);
    ok("a CertSpotter success carries no degradation and is not incomplete",
      !result.degradations && result.incomplete !== true && !result.ct_error, JSON.stringify(result.incomplete_reason));
    ok("CertSpotter names are discovered", result.items.includes("shop.example.com") && result.items.includes("www.example.com"));
    ok("discovery coverage records CertSpotter only",
      Object.keys(result.discovery_coverage?.per_provider || {}).every((key) => key.startsWith("certspotter_")),
      JSON.stringify(result.discovery_coverage?.per_provider));
    ok("discovery is complete for removal-anchoring purposes",
      subdomainDiscoveryComplete({ subdomains: result, dns_bruteforce: { items: [], error: null } }) === true);

    ok("a CertSpotter failure is total CT loss",
      failed.incomplete === true && failed.incomplete_reason === "ct_sources_unavailable" && !failed.degradations);
    ok("the failure names the queried provider", /^CT source failed — certspotter: /.test(failed.ct_error || ""), failed.ct_error);
    eq("the failed result still declares its provider set", failed.ct_providers, ["certspotter"]);
    ok("a failed discovery never anchors removal",
      subdomainDiscoveryComplete({ subdomains: failed, dns_bruteforce: { items: [], error: null } }) === false);

    const empty = await runSubdomainsModule("example.com", { ctCache: cacheWith(recorder({ certspotter: [] }).fetcher), cache: new Map() });
    ok("a successful empty CertSpotter answer stays a measured empty",
      empty.sources.certspotter.error === null && empty.incomplete !== true && !empty.ct_error);
  }

  // ── 4. Monitoring state and attack-surface completeness ─────────────────
  {
    const healthy = deriveSignalMonitoringStates({
      modules: { subdomains: result }, providerHealth: { certspotter: { outcome: "available" } },
    }).signals.certificate_transparency;
    eq("a CertSpotter success is healthy CT monitoring", healthy.state, "monitoring_healthy");
    eq("monitoring evidence lists CertSpotter only", Object.keys(healthy.evidence.providers), ["certspotter"]);
    const down = deriveSignalMonitoringStates({
      modules: { subdomains: failed }, providerHealth: { certspotter: { outcome: "unavailable" } },
    }).signals.certificate_transparency;
    ok("a CertSpotter outage is never healthy", down.state !== "monitoring_healthy", down.state);

    const brute = { items: [], checked: 40, error: null };
    const discovery = deriveAttackSurfaceSignalCompleteness({ subdomains: result, dns_bruteforce: brute }).signals.subdomain_discovery;
    eq("subdomain discovery names CertSpotter and brute force", discovery.sources, ["certspotter", "dns_bruteforce"]);
    const lost = deriveAttackSurfaceSignalCompleteness({ subdomains: failed, dns_bruteforce: brute }).signals.subdomain_discovery;
    ok("a CertSpotter outage never reads as complete discovery", lost.state !== "not_observed" && lost.reason !== "complete_discovery_no_hostname", JSON.stringify(lost.state));
  }

  // ── 5. Certificate intelligence ──────────────────────────────────────────
  {
    const certOk = runCertificateIntelligenceModule({ ssl: {}, subdomains: result }, "example.com");
    ok("certificate intelligence is not a blackout when CertSpotter answered", certOk.incomplete_reason !== "ct_sources_unavailable");
    eq("certificate intelligence counts CertSpotter only", Object.keys(certOk.ct_sources || {}), ["certspotter"]);
    const certDown = runCertificateIntelligenceModule({ ssl: {}, subdomains: failed }, "example.com");
    ok("a CertSpotter outage is a certificate CT blackout",
      certDown.incomplete === true && certDown.incomplete_reason === "ct_sources_unavailable");
    ok("the blackout wording speaks of one source",
      (certDown.suspicious_certificate_signals || []).some((s) => s.signal === "ct_sources_unavailable" && /^The Certificate Transparency source was unavailable/.test(s.description)));
  }

  // ── 6. SSL certificate fields and the shared-SAN measurement ────────────
  {
    const { calls, fetcher } = recorder();
    const ssl = await resolveCertificateTransparency("example.com", { ctCache: cacheWith(fetcher), now: () => NOW });
    eq("SSL reports CertSpotter only", Object.keys(ssl.ct_sources), ["certspotter"]);
    ok("SSL certificate fields come from CertSpotter", ssl.cert_not_after === "2099-12-01T00:00:00.000Z" && ssl.cert_issuer === "Spot CA");
    eq("no certificate subject is claimed from an issuance that carries none", ssl.cert_subject, null);
    eq("SSL contacts no other host", calls.other, []);
    eq("the shared-SAN count is measured from the SAN list", ssl.cert_shared_san_count, 0);
    eq("the measurement is recognised", sharedSanMeasured(ssl), true);
    const owned = buildCertificateOwnershipAssessment(ssl, "example.com");
    ok("a customer-only SAN list is customer-owned on its own names",
      owned.status === "customer_domain_certificate" && owned.customer_owned === true &&
      JSON.stringify(owned.evidence_signals) === JSON.stringify(["customer_san"]), JSON.stringify(owned));
    const projected = projectCertificateSharedSanForCustomer({
      ssl: { ...ssl, certificate_evidence: { schema_version: "external-certificate-observation-v3" } },
      certificateIntelligence: {}, domain: "example.com",
    }).shared_san_assessment;
    ok("the customer projection reads the zero as measured",
      projected.measurement_state === "measured_zero" && projected.assessment_state === "assessed", JSON.stringify(projected));

    const shared = await resolveCertificateTransparency("example.com", {
      ctCache: cacheWith(recorder({ certspotter: [issuance(["example.com", "unrelated.example.net"])] }).fetcher),
      now: () => NOW,
    });
    eq("an unrelated name on the SAN list is a measured shared SAN", shared.cert_shared_san_count, 1);
    eq("a shared certificate is assessed as shared",
      buildCertificateOwnershipAssessment(shared, "example.com").status, "shared_certificate");
    const wildcardOnly = await resolveCertificateTransparency("example.com", {
      ctCache: cacheWith(recorder({ certspotter: [issuance(["*.example.com"])] }).fetcher),
      now: () => NOW,
    });
    eq("without a subject, a wildcard-only certificate stays ownership-uncertain",
      buildCertificateOwnershipAssessment(wildcardOnly, "example.com").status, "ownership_uncertain");
    const lost = await resolveCertificateTransparency("example.com", {
      ctCache: cacheWith(recorder({ certspotter: 503 }).fetcher),
      now: () => NOW,
    });
    ok("a CertSpotter outage leaves the shared-SAN count unmeasured",
      lost.cert_shared_san_count === null && sharedSanMeasured(lost) === false);
  }

  // ── 7. Stored records keep the providers they recorded ──────────────────
  {
    // A neutral second provider name stands in for any provider a historical
    // record carries; readers must use the record, not the current policy.
    const historical = {
      items: ["www.example.com"], count: 1,
      sources: { retired_provider: { count: 0, error: "HTTP 502" }, certspotter: { count: 1, error: null } },
    };
    eq("a historical record is read with the providers it recorded",
      [...ctProvidersUsed(historical)], ["retired_provider", "certspotter"]);
    const state = deriveSignalMonitoringStates({
      modules: { subdomains: historical },
      providerHealth: { retired_provider: { outcome: "unavailable" }, certspotter: { outcome: "available" } },
    }).signals.certificate_transparency;
    ok("a historical record with one failed provider is never healthy", state.state !== "monitoring_healthy", state.state);
    ok("a historical record with one failed provider never anchors removal",
      subdomainDiscoveryComplete({ subdomains: historical, dns_bruteforce: { items: [], error: null } }) === false);
    const bothLost = { ...historical, items: [], count: 0,
      sources: { retired_provider: { count: 0, error: "HTTP 502" }, certspotter: { count: 0, error: "HTTP 503" } } };
    const bothLostIntel = runCertificateIntelligenceModule({ ssl: {}, subdomains: bothLost }, "example.com");
    ok("a historical record that lost every recorded provider is a blackout",
      bothLostIntel.incomplete_reason === "ct_sources_unavailable" &&
      bothLostIntel.suspicious_certificate_signals.some((s) => /^Both Certificate Transparency sources/.test(s.description || "")));
    const fallbackOnly = {
      cert_shared_san_count: null,
      ct_sources: { retired_provider: { count: 0, error: "HTTP 502" }, certspotter: { count: 1, error: null } },
    };
    eq("a historical record without a measured count stays unmeasured", sharedSanMeasured(fallbackOnly), false);
  }
} finally {
  globalThis.fetch = realFetch;
}

console.log(`\nCT CertSpotter-only policy: ${pass}/${pass + fail} passed`);
if (fail) { console.error("CT CertSpotter-only validation FAILED"); process.exit(1); }
console.log("CT CertSpotter-only validation passed");
