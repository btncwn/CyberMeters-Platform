#!/usr/bin/env node
//
// Production Certificate Transparency policy: CertSpotter only.
//
// crt.sh has no API contract or SLA and fails often; when it did, the whole scan
// was marked degraded and every domain read provisional. Production scans now
// query CertSpotter (documented, key-authenticated) only. This proves:
//   • production wiring (scan engine and free preview) declares CertSpotter only
//     and passes the SSLMate key from the Worker secret;
//   • crt.sh is never contacted and the key reaches only api.certspotter.com;
//   • a CertSpotter success is a COMPLETE CT result (no degradation), and a
//     CertSpotter failure is honest total CT loss — never healthy, never a
//     "fallback" to a provider that was not queried;
//   • monitoring state, attack-surface completeness, certificate intelligence
//     and SSL read the declared provider set, while an undeclared (historical)
//     record keeps the original two-provider meaning;
//   • the shared-SAN measurement survives: CertSpotter as the sole source
//     measures it from the full SAN list (never from a placeholder subject),
//     and a two-provider CertSpotter fallback stays unmeasured as before.
// Drives the real cache, orchestrator and modules. Node 24+.
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const enginePath = (f) => path.join(root, "workers", "scan-api", "src", "engines", f);
const eng = (f) => pathToFileURL(enginePath(f)).href;
const { CT_SCAN_PROVIDERS, CT_ALL_PROVIDERS, ctProvidersUsed } = await import(eng("ct-providers.js"));
const { createCertificateTransparencyCache } = await import(eng("ct-provider-cache.js"));
const { runSubdomainsModule } = await import(eng("subdomains-scan.js"));
const { resolveCertificateTransparency } = await import(eng("ssl-scan.js"));
const { deriveSignalMonitoringStates } = await import(eng("signal-monitoring-state.js"));
const { deriveAttackSurfaceSignalCompleteness } = await import(eng("attack-surface-signal-completeness.js"));
const { runCertificateIntelligenceModule, buildCertificateOwnershipAssessment, sharedSanMeasurementSource } = await import(eng("cert-intel.js"));
const { projectCertificateSharedSanForCustomer } = await import(
  pathToFileURL(path.join(root, "workers", "scan-api", "src", "routes", "certificate-shared-san-projection.js")).href);
const { subdomainDiscoveryComplete } = await import(eng("asset-inventory.js"));

let pass = 0, fail = 0;
const ok = (n, c, d = "") => { c ? pass++ : fail++; if (!c) console.log(`FAIL ${n}${d ? " — " + d : ""}`); };
const eq = (n, g, w) => ok(n, JSON.stringify(g) === JSON.stringify(w), `got ${JSON.stringify(g)} want ${JSON.stringify(w)}`);

const jsonResponse = (body, status = 200) => new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
const realFetch = globalThis.fetch;
globalThis.fetch = async (url) => String(url).includes("dns-query")
  ? jsonResponse({ Status: 0, Answer: [] })
  : new Response("", { status: 200 });

const NOW = Date.parse("2026-10-11T12:00:00.000Z");
const certSpotterBody = [
  { not_before: "2026-09-01T00:00:00.000Z", not_after: "2099-12-01T00:00:00.000Z", issuer: { name: "Spot CA" },
    dns_names: ["example.com", "www.example.com", "shop.example.com"] },
];
function recorder({ certspotter = certSpotterBody } = {}) {
  const calls = { crt_sh: 0, certspotter: 0, auth: [] };
  const fetcher = async (url, init = {}) => {
    const value = String(url);
    if (value.includes("crt.sh")) { calls.crt_sh += 1; return jsonResponse([]); }
    if (value.includes("api.certspotter.com")) {
      calls.certspotter += 1;
      calls.auth.push(init.headers?.Authorization ?? null);
      if (certspotter instanceof Error) throw certspotter;
      if (typeof certspotter === "number") return jsonResponse({}, certspotter);
      return jsonResponse(certspotter);
    }
    calls.other = (calls.other || 0) + 1;
    calls.auth.push(init.headers?.Authorization ?? null);
    return jsonResponse([]);
  };
  return { calls, fetcher };
}
const productionCache = (fetcher, apiKey = null) => createCertificateTransparencyCache({
  fetcher, enabledProviders: CT_SCAN_PROVIDERS, certspotterApiKey: apiKey,
  policies: { certspotter: { timeoutMs: 2_000, maxAttempts: 1, backoffMs: 0 } },
});

try {
  // ── 1. Policy and production wiring ────────────────────────────────────
  eq("production CT providers are CertSpotter only", [...CT_SCAN_PROVIDERS], ["certspotter"]);
  eq("an undeclared record keeps the original two providers", [...ctProvidersUsed({})], ["crt_sh", "certspotter"]);
  eq("a declared record is read as declared", [...ctProvidersUsed({ ct_providers: ["certspotter"] })], ["certspotter"]);
  eq("an unknown provider name never shrinks the set", [...ctProvidersUsed({ ct_providers: ["bogus"] })], [...CT_ALL_PROVIDERS]);
  {
    const engine = fs.readFileSync(enginePath("scan-engine.js"), "utf8");
    const billing = fs.readFileSync(path.join(root, "workers/scan-api/src/routes/billing.js"), "utf8");
    const wired = (src) => /createCertificateTransparencyCache\(\{[\s\S]{0,400}enabledProviders: CT_SCAN_PROVIDERS,\s*certspotterApiKey: env\?\.CERTSPOTTER_API_KEY \|\| null,/.test(src);
    ok("scan engine queries CertSpotter only, with the SSLMate key", wired(engine));
    ok("free preview queries CertSpotter only, with the SSLMate key", wired(billing));
  }

  // ── 2. crt.sh is never contacted; the key reaches only CertSpotter ──────
  {
    const { calls, fetcher } = recorder();
    const cache = productionCache(fetcher, "sslmate-test-key");
    const crt = await cache.get("example.com", "crt_sh");
    await cache.get("example.com", "certspotter");
    eq("crt.sh is never fetched", calls.crt_sh, 0);
    ok("asking for crt.sh returns an explicit not-used result, never data", crt.status === "unavailable" && crt.data === null);
    eq("the SSLMate key is sent as a bearer token to CertSpotter", calls.auth, ["Bearer sslmate-test-key"]);
    const { calls: noKey, fetcher: noKeyFetcher } = recorder();
    await productionCache(noKeyFetcher).get("example.com", "certspotter");
    eq("without a key no Authorization header is sent", noKey.auth, [null]);
  }

  // ── 3. Subdomains: success is complete, failure is honest total loss ────
  {
    const { calls, fetcher } = recorder();
    const result = await runSubdomainsModule("example.com", { ctCache: productionCache(fetcher, "k"), cache: new Map() });
    eq("CertSpotter-only discovery reports only CertSpotter", Object.keys(result.sources), ["certspotter"]);
    eq("the result declares its provider set", result.ct_providers, ["certspotter"]);
    ok("a CertSpotter success carries no degradation and is not incomplete",
      !result.degradations && result.incomplete !== true && !result.ct_error, JSON.stringify(result.degradations || result.incomplete_reason));
    ok("CertSpotter names are discovered", result.items.includes("shop.example.com") && result.items.includes("www.example.com"));
    eq("crt.sh was never contacted by the module", calls.crt_sh, 0);
    ok("discovery is complete for removal-anchoring purposes",
      subdomainDiscoveryComplete({ subdomains: result, dns_bruteforce: { items: [], error: null } }) === true);

    const failed = await runSubdomainsModule("example.com", { ctCache: productionCache(recorder({ certspotter: 503 }).fetcher), cache: new Map() });
    ok("a CertSpotter failure is total CT loss, never a fallback to an unqueried provider",
      failed.incomplete === true && failed.incomplete_reason === "ct_sources_unavailable" && !failed.degradations);
    ok("the failure names only the provider that was queried",
      /^CT source failed — certspotter: /.test(failed.ct_error || "") && !/crt\.sh/.test(failed.ct_error || ""), failed.ct_error);
    eq("the failed result still declares its provider set", failed.ct_providers, ["certspotter"]);

    const empty = await runSubdomainsModule("example.com", { ctCache: productionCache(recorder({ certspotter: [] }).fetcher), cache: new Map() });
    ok("a successful empty CertSpotter answer stays a measured empty, not a failure",
      empty.sources.certspotter.error === null && empty.incomplete !== true && !empty.ct_error);

    // ── 4. Monitoring state reads the declared provider set ───────────────
    const healthy = deriveSignalMonitoringStates({
      modules: { subdomains: result }, providerHealth: { certspotter: { outcome: "available" } },
    }).signals.certificate_transparency;
    eq("CertSpotter-only success is healthy CT monitoring", healthy.state, "monitoring_healthy");
    eq("monitoring evidence lists only the queried provider", Object.keys(healthy.evidence.providers), ["certspotter"]);
    const down = deriveSignalMonitoringStates({
      modules: { subdomains: failed }, providerHealth: { certspotter: { outcome: "unavailable" } },
    }).signals.certificate_transparency;
    ok("a CertSpotter outage is never healthy", down.state !== "monitoring_healthy", down.state);
    const legacy = deriveSignalMonitoringStates({
      modules: { subdomains: { ...result, ct_providers: undefined } }, providerHealth: { certspotter: { outcome: "available" } },
    }).signals.certificate_transparency;
    ok("an undeclared record missing crt.sh evidence is still not healthy", legacy.state !== "monitoring_healthy", legacy.state);

    // ── 5. Attack-surface completeness and certificate intelligence ───────
    const brute = { items: [], checked: 40, error: null };
    const discovery = deriveAttackSurfaceSignalCompleteness({ subdomains: result, dns_bruteforce: brute }).signals.subdomain_discovery;
    ok("subdomain discovery names only the queried CT provider", discovery.sources.includes("certspotter") && !discovery.sources.includes("crt_sh"), JSON.stringify(discovery.sources));
    const lostDiscovery = deriveAttackSurfaceSignalCompleteness({ subdomains: failed, dns_bruteforce: brute }).signals.subdomain_discovery;
    ok("a CertSpotter outage never reads as complete discovery", lostDiscovery.state !== "observed" || lostDiscovery.limitations?.length > 0, JSON.stringify(lostDiscovery));

    const certOk = runCertificateIntelligenceModule({ ssl: {}, subdomains: result }, "example.com");
    ok("certificate intelligence is not a blackout when CertSpotter answered", certOk.incomplete_reason !== "ct_sources_unavailable");
    eq("certificate intelligence counts only the queried provider", Object.keys(certOk.ct_sources || {}), ["certspotter"]);
    const certDown = runCertificateIntelligenceModule({ ssl: {}, subdomains: failed }, "example.com");
    ok("a CertSpotter outage is a certificate CT blackout, never healthy",
      certDown.incomplete === true && certDown.incomplete_reason === "ct_sources_unavailable");
    ok("the blackout wording speaks of one source",
      (certDown.suspicious_certificate_signals || []).some((s) => s.signal === "ct_sources_unavailable" && /^The Certificate Transparency source was unavailable/.test(s.description)));
  }

  // ── 6. SSL certificate fields from CertSpotter alone ────────────────────
  {
    const { calls, fetcher } = recorder();
    const ssl = await resolveCertificateTransparency("example.com", { ctCache: productionCache(fetcher), now: () => NOW });
    eq("SSL reports only the queried CT provider", Object.keys(ssl.ct_sources), ["certspotter"]);
    ok("SSL certificate fields come from CertSpotter", ssl.cert_not_after === "2099-12-01T00:00:00.000Z" && ssl.cert_issuer === "Spot CA");
    eq("SSL never contacts crt.sh", calls.crt_sh, 0);

    // Shared-SAN measurement: CertSpotter as the sole source carries the full
    // DNS SAN list, so the measurement survives the loss of crt.sh.
    eq("CertSpotter-only measures the shared-SAN count (all names are the customer's)", ssl.cert_shared_san_count, 0);
    eq("the measuring source is CertSpotter", sharedSanMeasurementSource(ssl), "certspotter");
    const owned = buildCertificateOwnershipAssessment(ssl, "example.com");
    ok("a customer-only SAN list is customer-owned on its own names, not on a placeholder subject",
      owned.status === "customer_domain_certificate" && owned.customer_owned === true &&
      JSON.stringify(owned.evidence_signals) === JSON.stringify(["customer_san"]), JSON.stringify(owned));
    const projected = projectCertificateSharedSanForCustomer({
      ssl: { ...ssl, certificate_evidence: { schema_version: "external-certificate-observation-v3" } },
      certificateIntelligence: {}, domain: "example.com",
    }).shared_san_assessment;
    ok("the customer projection reads a CertSpotter-only zero as measured",
      projected.measurement_state === "measured_zero" && projected.assessment_state === "assessed", JSON.stringify(projected));

    const shared = await resolveCertificateTransparency("example.com", {
      ctCache: productionCache(recorder({ certspotter: [{ ...certSpotterBody[0], dns_names: ["example.com", "unrelated.example.net"] }] }).fetcher),
      now: () => NOW,
    });
    eq("an unrelated name on the CertSpotter SAN list is a measured shared SAN", shared.cert_shared_san_count, 1);
    eq("a shared CertSpotter certificate is assessed as shared",
      buildCertificateOwnershipAssessment(shared, "example.com").status, "shared_certificate");

    const wildcardOnly = await resolveCertificateTransparency("example.com", {
      ctCache: productionCache(recorder({ certspotter: [{ ...certSpotterBody[0], dns_names: ["*.example.com"] }] }).fetcher),
      now: () => NOW,
    });
    eq("without a subject, a wildcard-only CertSpotter certificate stays ownership-uncertain",
      buildCertificateOwnershipAssessment(wildcardOnly, "example.com").status, "ownership_uncertain");

    // A two-provider record where crt.sh failed keeps its original meaning:
    // CertSpotter was a fallback and never measured shared SANs.
    const twoProvider = await resolveCertificateTransparency("example.com", {
      ctCache: createCertificateTransparencyCache({
        fetcher: async (url) => String(url).includes("crt.sh") ? jsonResponse({}, 403) : jsonResponse(certSpotterBody),
        policies: { crt_sh: { maxAttempts: 1, backoffMs: 0 }, certspotter: { maxAttempts: 1, backoffMs: 0 } },
      }),
      now: () => NOW,
    });
    ok("a two-provider record with crt.sh lost still reports both providers", "crt_sh" in twoProvider.ct_sources && "certspotter" in twoProvider.ct_sources);
    eq("a two-provider CertSpotter fallback still does not measure shared SANs", twoProvider.cert_shared_san_count, null);
    eq("a historical two-provider record with a CertSpotter count is still unmeasured",
      sharedSanMeasurementSource({ cert_shared_san_count: 0, ct_sources: { crt_sh: { count: 0, error: "HTTP 502" }, certspotter: { count: 1, error: null } } }), null);
    eq("a CertSpotter-only record whose CertSpotter source failed is unmeasured",
      sharedSanMeasurementSource({ cert_shared_san_count: 0, ct_sources: { certspotter: { count: 0, error: "HTTP 503" } } }), null);
  }
} finally {
  globalThis.fetch = realFetch;
}

console.log(`\nCT CertSpotter-only policy: ${pass}/${pass + fail} passed`);
if (fail) { console.error("CT CertSpotter-only validation FAILED"); process.exit(1); }
console.log("CT CertSpotter-only validation passed");
