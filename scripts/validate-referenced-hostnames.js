#!/usr/bin/env node
//
// Referenced hostnames: names under the scanned domain that the customer's own
// configuration points at (live certificate, website headers and redirects,
// MX/NS/SPF/DMARC records) join discovery only after DNS answers for them.
//
// Proves, against the real modules and the real scan engine:
//   • collection reads only evidence the scan holds, keeps only in-scope names
//     (never the domain itself, a wildcard, or another domain) and records
//     where each name was seen;
//   • confirmation costs one bounded DNS question per name, admits only names
//     DNS answers for, states every name it could not confirm and never checks
//     more than its cap;
//   • a durable scan admits confirmed names into discovery, takeover checks and
//     the asset inventory with their specific source; the compact waitUntil path
//     runs no lookup and says so;
//   • every recorded source has customer wording and counts as discovery
//     evidence for Shadow IT deferral.
// In-memory mutants of the module must each be rejected by the fixtures.
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const enginePath = (file) => path.join(root, "workers", "scan-api", "src", "engines", file);
const eng = (file) => import(pathToFileURL(enginePath(file)).href);
const modulePath = enginePath("referenced-hostnames.js");
const moduleSource = fs.readFileSync(modulePath, "utf8");

let pass = 0, fail = 0;
const ok = (name, condition, detail = "") => {
  if (condition) pass++;
  else { fail++; console.log(`FAIL ${name}${detail ? ` — ${detail}` : ""}`); }
};

// ── Fixtures shared by the real module and its mutants ─────────────────────
const LIVE_SSL = {
  live_certificate: {
    collection_complete: true,
    dns_names: ["example.com", "www.example.com", "*.example.com", "billing.example.com", "other.test"],
  },
  http_redirect_chain: {
    original_url: "http://example.com/",
    final_url: "https://login.example.com/",
    hop_observations: [{ hop: 1, url: "http://example.com/" }],
  },
};
const HEADERS = {
  response_url: "https://example.com/",
  raw_capture: {
    redirect_chain: [],
    headers_snapshot: {
      "content-security-policy": "default-src 'self' https://cdn.example.com https://cdn.vendor.test; report-uri https://r.example.com/csp",
      "content-security-policy-report-only": "script-src js.example.com",
      link: "<https://assets.example.com/site.css>; rel=preload; as=style",
      "access-control-allow-origin": "https://app.example.com",
    },
  },
};
const DNS = {
  mx_records: [{ value: "10 mail.example.com." }, { value: "20 mx.provider.test." }],
  nameservers: ["ns1.example.com.", "ns.provider.test."],
};
const SPF = "v=spf1 include:_spf.example.com a:relay.example.com ip4:192.0.2.1 include:vendor.test -all";
const DMARC = "v=DMARC1; p=reject; rua=mailto:dmarc@reports.example.com,https://agg.example.com/in";
const BIMI = "v=BIMI1; l=https://brand.example.com/logo.svg; a=https://certs.vendor.test/vmc.pem";

const EXPECTED_ORDER = [
  ["billing.example.com", ["live_tls_san"]],
  ["www.example.com", ["live_tls_san"]],
  ["mail.example.com", ["mx"]],
  ["ns1.example.com", ["ns"]],
  ["relay.example.com", ["spf"]],
  ["agg.example.com", ["dmarc"]],
  ["reports.example.com", ["dmarc"]],
  ["brand.example.com", ["bimi"]],
  ["login.example.com", ["redirect_chain"]],
  ["cdn.example.com", ["csp"]],
  ["js.example.com", ["csp"]],
  ["assets.example.com", ["link_header"]],
  ["app.example.com", ["cors_header"]],
];

const dohAnswer = (name, ip) => ({ Status: 0, Question: [{ name, type: 1 }], Answer: [{ name, type: 1, TTL: 60, data: ip }] });

async function fixtures(api) {
  let checks = 0;
  const collected = api.collectReferencedHostnames("example.com", {
    ssl: LIVE_SSL, headers: HEADERS, dns: DNS, spfRecord: SPF, dmarcRecord: DMARC, bimiRecord: BIMI,
  });
  assert.deepEqual(collected.candidates.map((c) => [c.hostname, c.sources]), EXPECTED_ORDER, "collection: exact in-scope names, sources and precedence order"); checks++;
  assert.deepEqual(collected.evidence_inputs,
    ["bimi", "cors_header", "csp", "dmarc", "link_header", "live_tls_san", "mx", "ns", "redirect_chain", "spf"], "collection: evidence inputs named"); checks++;
  for (const name of ["example.com", "other.test", "cdn.vendor.test", "mx.provider.test", "r.example.com", "_spf.example.com", "certs.vendor.test"]) {
    assert.ok(!collected.candidates.some((c) => c.hostname === name), `collection: ${name} is never a candidate`); checks++;
  }
  const incomplete = api.collectReferencedHostnames("example.com", {
    ssl: { live_certificate: { collection_complete: false, dns_names: ["billing.example.com"] } },
  });
  assert.deepEqual(incomplete.candidates, [], "collection: an incomplete live capture names nothing"); checks++;
  assert.deepEqual(api.collectReferencedHostnames("example.com", {}).candidates, [], "collection: no evidence, no candidates"); checks++;
  const shared = api.collectReferencedHostnames("example.com", {
    ssl: { live_certificate: { collection_complete: true, dns_names: ["cdn.example.com"] } }, headers: HEADERS,
  });
  assert.deepEqual(shared.candidates.find((c) => c.hostname === "cdn.example.com")?.sources, ["csp", "live_tls_san"], "collection: every place a name was seen is kept"); checks++;
  assert.equal(api.assetSourceForReferencedSources(["csp", "live_tls_san"]), "tls_certificate_name", "source precedence: certificate before CSP"); checks++;
  assert.equal(api.assetSourceForReferencedSources(["cors_header", "spf"]), "spf_reference", "source precedence: SPF before CORS"); checks++;
  assert.equal(api.assetSourceForReferencedSources(["unknown"]), null, "source precedence: unknown sources record nothing"); checks++;

  // Confirmation outcomes, both address questions per name.
  const responses = new Map([
    ["billing.example.com", dohAnswer("billing.example.com", "203.0.113.10")],
    ["www.example.com", dohAnswer("www.example.com", "203.0.113.11")],
    ["mail.example.com", { Status: 0, Answer: [{ name: "mail.example.com", type: 5, TTL: 60, data: "mail.provider.test." }] }],
    ["ns1.example.com", { Status: 3, Answer: [] }],
    ["relay.example.com", { Status: 0, Answer: [] }],
    ["agg.example.com", { Status: 2, Answer: [] }],
    ["reports.example.com", dohAnswer("reports.example.com", "198.51.100.7")],
  ]);
  const asked = [];
  const lookup = async (name, type) => {
    asked.push(`${type} ${name}`);
    if (name === "login.example.com") throw new Error("network down");
    return responses.get(name) ?? { Status: 3, Answer: [] };
  };
  const result = await api.confirmReferencedHostnames("example.com", collected, {
    exclude: ["www.example.com"], wildcardAddresses: ["198.51.100.7"], lookup,
  });
  assert.equal(asked.length, 2 * (EXPECTED_ORDER.length - 1), "confirmation: A and AAAA for each name not already discovered"); checks++;
  assert.ok(asked.every((q) => q.startsWith("A ") || q.startsWith("AAAA ")) && !asked.some((q) => q.endsWith(" www.example.com")), "confirmation: address questions only, discovered names skipped"); checks++;
  assert.deepEqual(result.confirmed.map((item) => [item.hostname, item.asset_source]), [
    ["billing.example.com", "tls_certificate_name"],
    ["mail.example.com", "mx_target"],
    ["reports.example.com", "dmarc_reference"],
  ], "confirmation: only names DNS answers for are admitted"); checks++;
  assert.deepEqual(result.confirmed[0].ip_addresses, ["203.0.113.10"], "confirmation: answered addresses are kept"); checks++;
  assert.equal(result.confirmed[1].alias_only, true, "confirmation: an alias without an address is marked alias-only"); checks++;
  assert.equal(result.confirmed[2].wildcard_match, true, "confirmation: a wildcard-shaped answer is flagged, not hidden"); checks++;
  assert.equal(result.not_found, 6, "confirmation: NXDOMAIN names are counted as not found"); checks++;
  assert.equal(result.no_address, 1, "confirmation: NOERROR without an address is counted as no address"); checks++;
  assert.equal(result.lookup_failed, 2, "confirmation: SERVFAIL and transport failures are counted as failed lookups"); checks++;
  assert.ok(result.executed === true && result.incomplete === true && result.incomplete_reason === "lookup_failed", "confirmation: failed lookups leave the step incomplete"); checks++;
  assert.equal(result.confirmed[0].dns?.A?.outcome, "answer", "confirmation: each family's outcome is kept"); checks++;

  // IPv6: a name with only an AAAA answer is confirmed with that address; a
  // dangling alias (the alias target does not exist) is kept as the name it is.
  const v6 = await api.confirmReferencedHostnames("example.com", {
    candidates: [{ hostname: "v6.example.com", sources: ["ns"] }, { hostname: "old.example.com", sources: ["csp"] }], evidence_inputs: ["ns", "csp"],
  }, {
    lookup: async (name, type) => (name === "v6.example.com"
      ? (type === "AAAA" ? { Status: 0, Answer: [{ name, type: 28, TTL: 60, data: "2001:db8::6" }] } : { Status: 0, Answer: [] })
      : { Status: 3, Answer: [{ name, type: 5, TTL: 60, data: "deleted.provider.test." }] }),
  });
  assert.deepEqual(v6.confirmed.map((item) => [item.hostname, item.ip_addresses]), [["v6.example.com", ["2001:db8::6"]], ["old.example.com", []]], "confirmation: an IPv6-only name and a dangling alias are both confirmed"); checks++;
  assert.ok(v6.confirmed[1].dangling_alias === true && v6.families.ipv6_only === 1, "confirmation: the dangling alias and the IPv6-only family are stated"); checks++;
  assert.equal(result.checked + result.not_checked, result.candidates_found, "confirmation: every candidate is either checked or counted"); checks++;

  const many = { candidates: Array.from({ length: 60 }, (_, i) => ({ hostname: `n${String(i).padStart(2, "0")}.example.com`, sources: ["csp"] })), evidence_inputs: ["csp"] };
  let questions = 0;
  const capped = await api.confirmReferencedHostnames("example.com", many, {
    lookup: async (name) => { questions++; return dohAnswer(name, "203.0.113.20"); },
  });
  assert.equal(questions, 100, "cap: at most 50 names, two questions each"); checks++;
  assert.ok(capped.checked === 50 && capped.not_checked === 10 && capped.confirmed.length === 50, "cap: the remainder is counted, not checked"); checks++;
  assert.equal(capped.incomplete_reason, "check_cap_reached", "cap: a reached cap is stated"); checks++;

  const clean = await api.confirmReferencedHostnames("example.com", { candidates: [{ hostname: "a.example.com", sources: ["mx"] }], evidence_inputs: ["mx"] }, {
    lookup: async (name) => dohAnswer(name, "203.0.113.30"),
  });
  assert.ok(clean.incomplete === false && clean.incomplete_reason === null, "confirmation: a clean run is complete"); checks++;

  assert.deepEqual(api.withConfirmedReferences(["a.example.com"], { confirmed: [{ hostname: "a.example.com" }, { hostname: "b.example.com" }] }),
    ["a.example.com", "b.example.com"], "merge: confirmed names append once"); checks++;
  const skipped = api.referencedHostnamesNotExecuted("invocation_not_durable", collected);
  assert.ok(skipped.executed === false && skipped.incomplete === true && skipped.confirmed.length === 0 &&
    skipped.not_checked === EXPECTED_ORDER.length, "not executed: nothing is claimed and every candidate is unchecked"); checks++;
  return checks;
}

// ── 1. The real module, then its mutants ────────────────────────────────────
const api = await import(pathToFileURL(modulePath).href);
try {
  pass += await fixtures(api);
} catch (error) {
  fail++;
  console.log(`FAIL referenced-hostname fixtures — ${error.message}`);
}
ok("module issues no request except through the injected DNS lookup",
  !/\bfetch\s*\(|safeFetch|probeAsset/.test(moduleSource) && (moduleSource.match(/dnsQuery\(/g) || []).length === 1);
ok("module confirms names through the shared discovery rule",
  /from "\.\/discovery-confirmation\.js"/.test(moduleSource) && !/classifyDiscoveryDnsResponse/.test(moduleSource));

// Relative imports are rewritten to absolute file URLs so a data: module can load them.
const absoluteImports = (source) => source.replace(/from "\.\/([^"]+)"/g,
  (_, file) => `from "${pathToFileURL(enginePath(file)).href}"`);
const MUTANTS = [
  ["if (confirmation.status === \"confirmed\") {", "if (confirmation.status !== \"not_found\") {", "an unconfirmed name is admitted"],
  ["const checks = pending.slice(0, REFERENCED_HOSTNAME_LIMITS.maxChecks);", "const checks = pending;", "the lookup cap is removed"],
  ["const confirmation = confirmationOf(observation, { wildcardSet, filterWildcard: false });",
    "const confirmation = confirmationOf(observation, { wildcardSet, filterWildcard: true });", "a referenced name is wildcard-filtered"],
  ["const live = ssl?.live_certificate?.collection_complete === true ? ssl.live_certificate : null;", "const live = ssl?.live_certificate ?? null;", "an incomplete live capture is trusted"],
  ["if (notChecked > 0) reasons.push(\"check_cap_reached\");", "", "a reached cap is hidden"],
  ["lookup_failed: counts.lookup_failed || 0,", "lookup_failed: 0,", "failed lookups are hidden"],
  ["!known.has(candidate.hostname) && candidate.hostname !== root", "candidate.hostname !== root", "discovered names are looked up again"],
  ["  live_tls_san:     \"tls_certificate_name\",\n  mx:               \"mx_target\",", "  mx:               \"mx_target\",\n  live_tls_san:     \"tls_certificate_name\",", "source precedence is reordered"],
];
for (const [before, after, label] of MUTANTS) {
  ok(`mutant anchor is unique: ${label}`, moduleSource.split(before).length === 2);
  const mutated = absoluteImports(moduleSource.replace(before, after));
  let killed = false;
  try {
    const mutant = await import(`data:text/javascript;base64,${Buffer.from(mutated).toString("base64")}`);
    await fixtures(mutant);
  } catch (error) {
    killed = error instanceof assert.AssertionError;
  }
  ok(`mutant rejected: ${label}`, killed);
}

// ── 2. Downstream contracts ─────────────────────────────────────────────────
const { REFERENCED_HOSTNAME_ASSET_SOURCES } = api;
const { assetSourceLabel } = await import(pathToFileURL(path.join(root, "frontend", "src", "lib", "assetSourceLabel.js")).href);
for (const code of Object.values(REFERENCED_HOSTNAME_ASSET_SOURCES)) {
  ok(`asset source ${code} has customer wording`, assetSourceLabel(code) !== code && assetSourceLabel(code) !== "—", assetSourceLabel(code));
}
const shadowSource = fs.readFileSync(enginePath("shadow-it-inventory.js"), "utf8");
ok("Shadow IT treats every referenced asset source as discovery evidence",
  /const DISCOVERY_ASSET_SOURCES = new Set\(\[[^\]]*?\.\.\.Object\.values\(REFERENCED_HOSTNAME_ASSET_SOURCES\),[^\]]*\]\);/.test(shadowSource));
const { OUTBOUND_FULLY_INSTRUMENTED_MODULES } = await eng("scan-budget.js");
ok("the lookup step's outbound calls are fully instrumented", OUTBOUND_FULLY_INSTRUMENTED_MODULES.has("referenced_hostnames"));

const { deriveAttackSurfaceSignalCompleteness } = await eng("attack-surface-signal-completeness.js");
const withStep = deriveAttackSurfaceSignalCompleteness({
  subdomains: { items: ["billing.example.com"], count: 1, error: null,
    referenced_hostnames: { executed: true, incomplete: true, incomplete_reason: "lookup_failed", confirmed: [] } },
  dns_bruteforce: { items: [], checked: 56, error: null },
}).signals.subdomain_discovery;
ok("discovery names the referenced step as a source when it ran",
  withStep.sources.includes("referenced_hostnames") && withStep.limitations.includes("referenced_hostnames_lookup_failed"),
  JSON.stringify(withStep));
const withoutStep = deriveAttackSurfaceSignalCompleteness({
  subdomains: { items: [], count: 0, error: null,
    referenced_hostnames: { executed: false, incomplete: true, incomplete_reason: "invocation_not_durable" } },
  dns_bruteforce: { items: [], checked: 56, error: null },
}).signals.subdomain_discovery;
ok("a step that did not run is never named as a source", !withoutStep.sources.includes("referenced_hostnames"), JSON.stringify(withoutStep.sources));

// ── 3. Real engine traces ───────────────────────────────────────────────────
const { runScanEngine } = await eng("scan-engine.js");
const { liveTlsProbeBinding } = await import(pathToFileURL(path.join(root, "scripts", "lib", "live-tls-fixture.mjs")).href);
const realFetch = globalThis.fetch;
const RESOLVING = new Map([
  ["example.com", "93.184.216.34"],
  ["www.example.com", "93.184.216.34"],
  ["billing.example.com", "203.0.113.10"],
  ["static.example.com", "203.0.113.12"],
]);

async function traceEngine(executionContext) {
  const dnsQuestions = [];
  const inserts = [];
  let report = null;
  globalThis.fetch = async (input) => {
    const url = new URL(String(input));
    if (url.hostname === "cloudflare-dns.com" || url.hostname === "dns.google") {
      const name = url.searchParams.get("name") || "";
      const type = url.searchParams.get("type") || "A";
      dnsQuestions.push(`${type} ${name}`);
      if (name === "retired.example.com") return Response.json({ Status: 3, Answer: [] });
      if (type === "A" && RESOLVING.has(name)) {
        return Response.json({ Status: 0, Answer: [{ name, type: 1, TTL: 60, data: RESOLVING.get(name) }] });
      }
      return Response.json({ Status: 0, Answer: [] });
    }
    if (url.protocol === "https:" || url.protocol === "http:") {
      return new Response("<html><title>Site</title></html>", { status: 200, headers: {
        "content-type": "text/html",
        "content-security-policy": "default-src 'self' https://static.example.com https://retired.example.com",
      } });
    }
    return Response.json({});
  };
  const r2 = new Map();
  const statement = (sql, args = []) => ({
    sql,
    args,
    bind: (...bound) => statement(sql, bound),
    run: async () => ({ success: true, meta: { changes: /INSERT OR IGNORE INTO scan_report_snapshots|SET status = 'completed'/.test(sql) ? 1 : 0 } }),
    all: async () => ({ results: /FROM workspace_domains wd\s+JOIN workspaces w/.test(sql) ? [{ workspace_id: "ws_ref" }] : [] }),
    first: async () => (/SELECT id FROM workspaces WHERE id = \? AND deleted_at IS NULL/.test(sql) ? { id: args[0] } : null),
  });
  const env = {
    cybermeters_db: {
      prepare: (sql) => statement(sql),
      batch: async (statements) => {
        for (const item of statements) {
          if (/INSERT OR IGNORE INTO workspace_assets/.test(item.sql)) inserts.push({ hostname: item.args[3], source: item.args[5] });
        }
        return statements.map(() => ({ results: [], success: true, meta: { changes: 0 } }));
      },
    },
    cybermeters_reports: {
      put: async (key, body) => {
        r2.set(String(key), String(body));
        if (String(key) === "reports/scan_ref.json") report = JSON.parse(String(body));
        return {};
      },
      get: async (key) => (r2.has(String(key)) ? { text: async () => r2.get(String(key)), json: async () => JSON.parse(r2.get(String(key))) } : null),
      delete: async () => ({}),
    },
    NETWORK_PROBE: liveTlsProbeBinding({ dnsNames: ["example.com", "www.example.com", "billing.example.com", "*.example.com"] }),
    APP_VERSION: "test",
  };
  let threw = null;
  try {
    await runScanEngine("scan_ref", "dom_ref", "ws_ref", "example.com", env, { executionContext });
  } catch (error) { threw = error; }
  globalThis.fetch = realFetch;
  return { threw, report, dnsQuestions, inserts };
}

const durable = await traceEngine("queue");
ok("durable trace completes", durable.threw === null && durable.report !== null, String(durable.threw));
const referenced = durable.report?.modules?.subdomains?.referenced_hostnames;
ok("durable: the lookup step ran", referenced?.executed === true, JSON.stringify(referenced));
ok("durable: certificate and CSP names DNS answers for are confirmed with their source",
  JSON.stringify((referenced?.confirmed || []).map((item) => [item.hostname, item.asset_source]).sort()) ===
    JSON.stringify([["billing.example.com", "tls_certificate_name"], ["static.example.com", "csp_reference"]]),
  JSON.stringify(referenced?.confirmed));
ok("durable: a referenced name that does not exist is counted, not admitted",
  referenced?.not_found >= 1 && !(durable.report?.modules?.subdomains?.items || []).includes("retired.example.com"),
  JSON.stringify({ not_found: referenced?.not_found, items: durable.report?.modules?.subdomains?.items }));
ok("durable: confirmed names join the discovered set",
  ["billing.example.com", "static.example.com"].every((host) => (durable.report?.modules?.subdomains?.items || []).includes(host)),
  JSON.stringify(durable.report?.modules?.subdomains?.items));
ok("durable: takeover checks the confirmed names",
  ["billing.example.com", "static.example.com"].every((host) => durable.dnsQuestions.includes(`CNAME ${host}`)),
  durable.dnsQuestions.filter((q) => q.startsWith("CNAME")).join(", "));
ok("durable: the inventory records each confirmed name with its specific source",
  durable.inserts.some((row) => row.hostname === "billing.example.com" && row.source === "tls_certificate_name") &&
    durable.inserts.some((row) => row.hostname === "static.example.com" && row.source === "csp_reference") &&
    !durable.inserts.some((row) => row.hostname === "retired.example.com"),
  JSON.stringify(durable.inserts));
ok("durable: each referenced name was asked about once per family",
  ["billing.example.com", "static.example.com", "retired.example.com"].every((host) =>
    durable.dnsQuestions.filter((q) => q === `A ${host}`).length === 1 && durable.dnsQuestions.filter((q) => q === `AAAA ${host}`).length <= 1),
  durable.dnsQuestions.filter((q) => /(billing|static|retired)\./.test(q)).join(", "));
const telemetryRow = (durable.report?.execution_diagnostics?.modules || []).find((row) => row?.module === "referenced_hostnames");
ok("durable: the lookup step has its own measured telemetry row",
  telemetryRow?.outbound_measurement_complete === true && telemetryRow?.outbound_attempts_observed === 6, JSON.stringify(telemetryRow));
ok("durable: discovery names the referenced step as a source",
  (durable.report?.modules?.attack_surface_signal_completeness?.signals?.subdomain_discovery?.sources || []).includes("referenced_hostnames"),
  JSON.stringify(durable.report?.modules?.attack_surface_signal_completeness?.signals?.subdomain_discovery));

const compact = await traceEngine("waituntil");
ok("waitUntil trace completes", compact.threw === null && compact.report !== null, String(compact.threw));
const skipped = compact.report?.modules?.subdomains?.referenced_hostnames;
ok("waitUntil: the step states it did not run",
  skipped?.executed === false && skipped?.reason === "invocation_not_durable" && skipped?.confirmed?.length === 0,
  JSON.stringify(skipped));
ok("waitUntil: no referenced name is looked up",
  !compact.dnsQuestions.some((q) => /^A (billing|static|retired)\.example\.com$/.test(q)),
  compact.dnsQuestions.filter((q) => /(billing|static|retired)\./.test(q)).join(", "));

console.log(`\nreferenced hostnames: ${pass} passed, ${fail} failed`);
process.exit(fail === 0 ? 0 : 1);
