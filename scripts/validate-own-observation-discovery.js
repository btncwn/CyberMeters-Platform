#!/usr/bin/env node
//
// Own-observation guard: CyberMeters discovers hostnames and reads certificates
// only through its own observation — DNS queries, its own HTTP fetches and the
// live TLS handshake. No product code depends on a third-party certificate-log
// or hostname data service.
//
// Proves, by reading product sources and driving the real modules:
//   • the retired provider modules are gone and nothing imports them;
//   • no product source names a certificate-log search service (checked by
//     token hash, so this file names none either);
//   • only listed historical readers mention the retired certificate-log
//     concept, so a new producer cannot slip in;
//   • subdomain discovery issues DNS-over-HTTPS questions only;
//   • without a captured live leaf, certificate facts are unknown, the module
//     is incomplete and the risk level is never favourable;
//   • monitoring and certificate signal models carry no certificate-log signal;
//   • discovery coverage is always bounded — never a complete-inventory claim;
//   • the free preview runs no discovery module.
// Mutation-backed: the token and concept scanners are fed planted inputs and
// must flag them.
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const enginePath = (f) => path.join(root, "workers", "scan-api", "src", "engines", f);
const eng = (f) => pathToFileURL(enginePath(f)).href;

let pass = 0, fail = 0;
const ok = (n, c, d = "") => { c ? pass++ : fail++; if (!c) console.log(`FAIL ${n}${d ? " — " + d : ""}`); };

// ── Product source inventory ────────────────────────────────────────────────
const PRODUCT_ROOTS = [
  path.join(root, "workers", "scan-api", "src"),
  path.join(root, "workers", "email-ingest", "src"),
  path.join(root, "workers", "network-probe", "src"),
  path.join(root, "frontend", "src"),
  path.join(root, "shared"),
];
function walk(dir, out = []) {
  if (!fs.existsSync(dir)) return out;
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      if (entry.name === "node_modules" || entry.name === "__tests__") continue;
      walk(full, out);
    } else if (/\.(m?js|jsx|ts|tsx|json|html|css)$/.test(entry.name)) {
      out.push(full);
    }
  }
  return out;
}
const productFiles = PRODUCT_ROOTS.flatMap((dir) => walk(dir));
const rel = (file) => path.relative(root, file).split(path.sep).join("/");
ok("product source inventory is non-trivial", productFiles.length > 200, `${productFiles.length} files`);

// ── 1. Retired provider modules ─────────────────────────────────────────────
const RETIRED_MODULES = ["ct-providers.js", "ct-provider-cache.js", "ct-first-success.js"];
for (const name of RETIRED_MODULES) {
  ok(`retired module ${name} is deleted`, !fs.existsSync(enginePath(name)));
}
const retiredImport = /from\s+["'][^"']*\/(ct-providers|ct-provider-cache|ct-first-success)(\.js)?["']|import\(\s*["'][^"']*\/(ct-providers|ct-provider-cache|ct-first-success)/;
const importers = productFiles.filter((file) => retiredImport.test(fs.readFileSync(file, "utf8")));
ok("no product file imports a retired provider module", importers.length === 0, importers.map(rel).join(", "));

// ── 2. No certificate-log search service is named (token hashes) ────────────
const FORBIDDEN_TOKEN_SHA256 = new Set([
  "8a301c6ea81095116d0e5f6f39ea01a2ca40d68ba14c95e5295b315b5d9d5ff5",
  "f6da92f871878f0651619d89afdc2c2d09ffd876574ba441b78e5476e1a9f9b8",
  "d535ccf4c31c7ab2e001249a5587fbe8433f82aad7a353d696b21c0661aac9cf",
  "03c21d445bf45fc582e900ca135e61e574fed76050b474ba9583b22eda81c35e",
  "af237127e80663f535bd8b09d58f63089d857d803ee44e3ffdb4dd80f1f5a479",
  "b1a4759d6f2ecca205f46492c68d3ea7be318bf04d2dec39c2d28a45802ae3c7",
  "22dea3143f128a928736b87c288c3c0f49e7837292fdf82a06e29203b1638caa",
]);
const sha256 = (value) => crypto.createHash("sha256").update(value).digest("hex");
export function forbiddenServiceTokens(text) {
  const hits = new Set();
  for (const raw of String(text).toLowerCase().split(/[^a-z0-9.\-]+/)) {
    const token = raw.replace(/^[.\-]+|[.\-]+$/g, "");
    if (!token) continue;
    const parts = token.split(".");
    const candidates = new Set([token, ...parts]);
    for (let i = 1; i < parts.length; i += 1) candidates.add(parts.slice(i).join("."));
    for (const candidate of candidates) {
      if (FORBIDDEN_TOKEN_SHA256.has(sha256(candidate))) hits.add(sha256(candidate).slice(0, 12));
    }
  }
  return [...hits];
}
const namingFiles = productFiles
  .map((file) => [file, forbiddenServiceTokens(fs.readFileSync(file, "utf8"))])
  .filter(([, hits]) => hits.length > 0);
ok("no product source names a certificate-log search service", namingFiles.length === 0,
  namingFiles.map(([file, hits]) => `${rel(file)} (${hits.join(",")})`).join(", "));

// ── 3. Only listed historical readers mention the retired concept ───────────
// Each file here reads stored history (old assets, events, findings, reports)
// or teaches what attackers do; none produces the retired evidence.
const HISTORICAL_READERS = new Set([
  "workers/scan-api/src/engines/identity-evidence-contract.js",
  "workers/scan-api/src/engines/vendor-risk.js",
  "workers/scan-api/src/engines/shadow-it-inventory.js",
  "frontend/src/lib/assetSourceLabel.js",
  "frontend/src/data/academy.js",
]);
const CONCEPT = /certificate[ _-]?transparency/i;
const conceptFiles = productFiles.filter((file) => CONCEPT.test(fs.readFileSync(file, "utf8")));
const unexpected = conceptFiles.map(rel).filter((file) => !HISTORICAL_READERS.has(file));
ok("only listed historical readers mention the retired certificate-log concept", unexpected.length === 0, unexpected.join(", "));
for (const reader of HISTORICAL_READERS) {
  ok(`historical reader ${reader} still exists`, fs.existsSync(path.join(root, reader)));
}

// Scanner mutations: planted inputs must be flagged.
ok("M1 token scanner flags a planted service host", forbiddenServiceTokens("fetch('https://api." + "cert" + "spotter.com/v1/x')").length === 1);
ok("M2 token scanner flags a planted bare service name", forbiddenServiceTokens("const u = 'https://" + "crt" + ".sh/?q=x'").length === 1);
ok("M3 token scanner leaves ordinary hosts alone", forbiddenServiceTokens("https://cloudflare-dns.com/dns-query example.com").length === 0);
ok("M4 concept scanner flags a planted producer", CONCEPT.test("source: \"certificate_" + "transparency\""));

// ── 4. Discovery issues DNS-over-HTTPS questions only ───────────────────────
const { runSubdomainsModule, SUBDOMAIN_DISCOVERY_SOURCE } = await import(eng("subdomains-scan.js"));
const realFetch = globalThis.fetch;
const contacted = [];
globalThis.fetch = async (url) => {
  contacted.push(String(url));
  return new Response(JSON.stringify({ Status: 3, Answer: [] }), {
    status: 200,
    headers: { "content-type": "application/dns-json" },
  });
};
try {
  const sub = await runSubdomainsModule("example.com", {});
  ok("discovery result names its own source", sub.source === SUBDOMAIN_DISCOVERY_SOURCE && sub.source === "dns_discovery", sub.source);
  ok("discovery contacted only the DNS-over-HTTPS resolver",
    contacted.length > 0 && contacted.every((url) => url.startsWith("https://cloudflare-dns.com/dns-query?")),
    contacted.join(" | "));
  ok("discovery result carries no provider fields",
    !("sources" in sub) && !("ct_sources" in sub) && !("ct_error" in sub), JSON.stringify(Object.keys(sub)));
} finally {
  globalThis.fetch = realFetch;
}

// ── 5. Certificates come only from the live leaf ────────────────────────────
const { runCertificateIntelligenceModule } = await import(eng("cert-intel.js"));
const { CERTIFICATE_SIGNAL_KEYS, deriveCertificateSignalCompletenessFromModules } = await import(eng("certificate-signal-completeness.js"));
ok("certificate signal model has no certificate-log signal",
  !CERTIFICATE_SIGNAL_KEYS.includes("certificate_transparency") && CERTIFICATE_SIGNAL_KEYS.length === 14,
  JSON.stringify(CERTIFICATE_SIGNAL_KEYS));
// A stored-looking record with the retired raw fields must not leak back in.
const staleSsl = {
  tls_state: "observed_present",
  https_available: true,
  cert_issuer: "Some CA",
  cert_not_after: "2099-01-01T00:00:00.000Z",
  cert_san_names: ["example.com"],
};
const unobserved = deriveCertificateSignalCompletenessFromModules({ modules: { ssl: staleSsl } });
for (const key of ["san", "issuer", "expiry", "wildcard"]) {
  ok(`without a live leaf the ${key} signal is unknown and incomplete`,
    unobserved.signals[key].observation === "unknown" &&
      unobserved.signals[key].completeness_state === "evidence_incomplete" &&
      unobserved.signals[key].observation_scope === "live_tls",
    JSON.stringify(unobserved.signals[key]));
}
ok("summary carries no certificate-log fields",
  !("ct_only" in unobserved.summary) && !("ct_issuance_observed" in unobserved.summary));
const ci = runCertificateIntelligenceModule({ ssl: staleSsl, subdomains: { items: [], wildcard_dns: false } }, "example.com");
ok("certificate intelligence without a live leaf is incomplete, not observed",
  ci.incomplete === true && ci.incomplete_reason === "certificate_not_observed" && ci.evidence_source === "not_observed",
  JSON.stringify({ incomplete: ci.incomplete, reason: ci.incomplete_reason, source: ci.evidence_source }));
ok("certificate intelligence never reads the retired raw fields", ci.issuer === null && ci.expires_at === null, JSON.stringify({ issuer: ci.issuer, expires_at: ci.expires_at }));
ok("certificate risk without a live leaf is unknown, never low", ci.certificate_risk_level === "unknown", ci.certificate_risk_level);
ok("certificate intelligence names live TLS as its source", ci.source === "live_tls");

// ── 6. Monitoring signals ───────────────────────────────────────────────────
const { SIGNAL_MONITORING_DEFINITIONS, deriveSignalMonitoringStates } = await import(eng("signal-monitoring-state.js"));
ok("monitoring definitions carry no certificate-log signal", !("certificate_transparency" in SIGNAL_MONITORING_DEFINITIONS));
ok("monitoring definitions depend on no data provider",
  Object.values(SIGNAL_MONITORING_DEFINITIONS).every((definition) => !("providers" in definition)));
const states = deriveSignalMonitoringStates({ modules: {} });
ok("monitoring states never report the retired signal", !("certificate_transparency" in states.signals));

// ── 7. Discovery coverage is always bounded ─────────────────────────────────
const { deriveAttackSurfaceSignalCompleteness } = await import(eng("attack-surface-signal-completeness.js"));
const completeEmpty = deriveAttackSurfaceSignalCompleteness({
  subdomains: { items: [], count: 0, wildcard_dns: false, error: null, source: "dns_discovery" },
  dns_bruteforce: { items: [], checked: 40, error: null },
  technology_detection: { linked_hostnames: [] },
});
const discovery = completeEmpty.signals.subdomain_discovery;
ok("an empty finished discovery is not_observed under bounded coverage",
  discovery.state === "not_observed" && discovery.reason === "bounded_discovery_no_hostname" && discovery.coverage_state === "bounded",
  JSON.stringify(discovery));
ok("discovery sources are CyberMeters' own observations",
  discovery.sources.every((source) => ["dns_bruteforce", "dns_srv", "html_link", "referenced_hostnames"].includes(source)), JSON.stringify(discovery.sources));
const failedWildcard = deriveAttackSurfaceSignalCompleteness({
  subdomains: { items: [], count: 0, incomplete: true, incomplete_reason: "wildcard_check_failed", error: null },
  dns_bruteforce: { items: [], checked: 40, error: null },
});
ok("a failed wildcard check keeps an empty discovery incomplete",
  failedWildcard.signals.subdomain_discovery.state === "incomplete", JSON.stringify(failedWildcard.signals.subdomain_discovery));
const found = deriveAttackSurfaceSignalCompleteness({
  subdomains: { items: ["a.example.com"], count: 1, error: null },
  dns_bruteforce: { items: [{ hostname: "a.example.com" }, { hostname: "w.example.com", wildcard_match: true }], checked: 40, error: null },
});
ok("observed hostnames count once and exclude wildcard matches",
  found.signals.subdomain_discovery.state === "observed" && found.signals.subdomain_discovery.evidence_count === 1,
  JSON.stringify(found.signals.subdomain_discovery));

// ── 8. Free preview and budget ──────────────────────────────────────────────
const { FREE_SCAN_MODULE_DEFINITIONS } = await import(eng("free-scan-evidence.js"));
ok("free preview runs no discovery module",
  FREE_SCAN_MODULE_DEFINITIONS.every((definition) => definition.module !== "subdomains") && FREE_SCAN_MODULE_DEFINITIONS.length === 5,
  JSON.stringify(FREE_SCAN_MODULE_DEFINITIONS.map((definition) => definition.module)));
const { MODULE_SUBREQUEST_COST } = await import(eng("scan-budget.js"));
ok("discovery wildcard check is budgeted at two DNS questions", MODULE_SUBREQUEST_COST.subdomains === 2, String(MODULE_SUBREQUEST_COST.subdomains));

// ── 9. The whole scan against the lab's stand-in internet ───────────────────
// scripts/lab/: a fake DNS/HTTP/TLS world that records every request and fails
// closed for anything it does not know, driving the real engine and storage.
const { runLabChecks } = await import(pathToFileURL(path.join(root, "scripts", "lab", "lab-checks.mjs")).href);
await runLabChecks({ ok, root });

console.log(`\nown-observation discovery: ${pass} passed, ${fail} failed`);
process.exit(fail === 0 ? 0 : 1);
