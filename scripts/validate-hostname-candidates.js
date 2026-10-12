#!/usr/bin/env node
// Pure extraction fixtures and in-memory mutants; no product files are changed.
import assert from "node:assert/strict";
import fs from "node:fs";
import { fileURLToPath } from "node:url";

const moduleUrl = new URL("../workers/scan-api/src/engines/hostname-candidates.js", import.meta.url);
const source = fs.readFileSync(fileURLToPath(moduleUrl), "utf8");

function fixtures(api) {
  let checks = 0;
  const eq = (got, want, label) => { assert.deepEqual(got, want, label); checks++; };
  const ok = (value, label) => { assert.ok(value, label); checks++; };
  const run = (sources, domain = "example.com") => api.extractHostnameCandidates({
    domain, observedAt: "2026-10-12T00:00:00.000Z", sources,
  });
  const names = (result) => result.candidates.map((item) => item.hostname);
  const merged = run({ liveTlsDnsNames: ["API.EXAMPLE.COM."], linkedHostnames: ["api.example.com"] });
  eq(merged.candidates, [{ hostname: "api.example.com", sources: ["linked_hostnames", "live_tls_san"] }], "merge independent sources");
  eq(merged.version, "hostname-candidates-v1", "contract version");
  eq(merged.root, "example.com", "canonical root");
  eq(merged.observed_at, "2026-10-12T00:00:00.000Z", "caller timestamp preserved");
  eq(Object.keys(merged).sort(), ["version", "root", "observed_at", "candidates", "wildcard_scopes", "out_of_scope_count", "rejected_count", "truncated", "truncated_count"].sort(), "exact result contract");
  eq(names(run({ linkedHostnames: ["api.bücher.example", "API.XN--BCHER-KVA.EXAMPLE."] }, "BÜCHER.EXAMPLE.")), ["api.xn--bcher-kva.example"], "IDN forms deduplicate");
  eq(api.normalizeHostname("api。example。com。"), "api.example.com", "Unicode dots normalize");
  const outside = run({ linkedHostnames: ["example.com.evil.test", "evilexample.com", "example.com", "good.example.com"] });
  eq(names(outside), ["good.example.com"], "strict domain boundary and root excluded");
  eq(outside.out_of_scope_count, 2, "outside count only");
  ok(!JSON.stringify(outside).includes("evil"), "outside names do not leak");
  const wildcard = run({ liveTlsDnsNames: ["*.example.com", "*.CDN.EXAMPLE.COM.", "a.*.example.com", "*.evil.test"] });
  eq(wildcard.candidates, [], "wildcards are never candidates");
  eq(wildcard.wildcard_scopes, ["cdn.example.com", "example.com"], "wildcard scopes are bare sorted names");
  eq(wildcard.rejected_count, 1, "interior wildcard rejected");
  eq(wildcard.out_of_scope_count, 1, "outside wildcard count");
  const csp = run({ csp: "default-src 'self' 'none' * https: data: 'nonce-abc' 'sha256-Zm9v' 'unsafe-inline'; connect-src https://api.example.com:8443/path wss://rt.example.com *.cdn.example.com; report-uri https://report.example.com; report-to reports.example.com" });
  eq(names(csp), ["api.example.com", "rt.example.com"], "CSP host tokens only");
  eq(csp.wildcard_scopes, ["cdn.example.com"], "CSP wildcard separated");
  eq(csp.candidates[0].sources, ["csp"], "CSP source recorded");
  eq(names(run({ csp: "img-src img.example.com:*; SCRIPT-SRC scripts.example.com, connect-src second.example.com" })), ["img.example.com", "scripts.example.com", "second.example.com"], "CSP wildcard port and combined policies");
  eq(names(run({ csp: "connect-src https://user:pass@api.example.com https://api.example.com/?x=1" })), [], "invalid host-source forms ignored");
  for (const invalid of ["https:///api.example.com", "//api.example.com", "https://%61pi.example.com", "https://api.example.com\\wrong"]) {
    eq(names(run({ csp: `connect-src ${invalid}` })), [], "URL repair must not create CSP hostname evidence");
  }
  eq(names(run({ csp: "connect-src https://api.example.com:*/valid%20path" })), ["api.example.com"], "valid wildcard port and encoded path remain supported");
  eq(names(run({ csp: "connect-src https://api.bücher.example:443/path" }, "bücher.example")), ["api.xn--bcher-kva.example"], "valid IDN CSP host remains supported");
  const dns = run({ mxValues: ["10 mail.example.com.", "0 .", ".", "20 outside.test"], srvTargets: ["srv.example.com."], nameservers: ["NS1.EXAMPLE.COM."] });
  eq(names(dns), ["mail.example.com", "ns1.example.com", "srv.example.com"], "DNS sources extract hostname");
  eq(dns.candidates.map((c) => c.sources), [["mx"], ["ns"], ["srv"]], "DNS provenance");
  eq(dns.out_of_scope_count, 1, "external DNS provider excluded");
  eq(dns.rejected_count, 0, "null MX ignored");
  eq(api.normalizeHostname("a".repeat(63) + ".example.com"), "a".repeat(63) + ".example.com", "63 byte label valid");
  eq(api.normalizeHostname("a".repeat(64) + ".example.com"), null, "64 byte label rejected");
  const maxHost = `${"a".repeat(63)}.${"b".repeat(63)}.${"c".repeat(63)}.${"d".repeat(61)}`;
  eq(api.normalizeHostname(maxHost), maxHost, "253 byte hostname valid");
  eq(api.normalizeHostname(maxHost + "d"), null, "254 byte hostname rejected");
  for (const invalid of ["-api.example.com", "api-.example.com", "a..example.com", "_srv.example.com", "https://api.example.com", "api.example.com:443", "a@example.com", "a%2eexample.com", "a\\example.com", "127.0.0.1", "a\u0000.example.com"]) {
    eq(api.normalizeHostname(invalid), null, `invalid hostname ${JSON.stringify(invalid)}`);
  }
  const countCap = run({ linkedHostnames: Array.from({ length: 205 }, (_, i) => `h${String(i).padStart(3, "0")}.example.com`) });
  eq(countCap.candidates.length, 200, "candidate cap");
  eq(countCap.truncated_count, 5, "distinct capped candidate count");
  eq(countCap.truncated, true, "candidate truncation flagged");
  const itemCap = run({ linkedHostnames: Array(502).fill("api.example.com") });
  eq(itemCap.candidates.length, 1, "dedupe under list cap");
  eq(itemCap.truncated_count, 2, "omitted list entries counted");
  const oversized = run({ csp: "a".repeat(16_385), linkedHostnames: ["é".repeat(8_193)] });
  eq(oversized.candidates, [], "oversized strings not partially interpreted");
  eq(oversized.truncated_count, 2, "UTF8 byte and ASCII caps counted");
  eq(oversized.truncated, true, "input truncation flagged");
  const boundaryCsp = "connect-src api.example.com";
  eq(names(run({ csp: boundaryCsp + " ".repeat(16_384 - boundaryCsp.length) })), ["api.example.com"], "input byte boundary inclusive");
  const tokenCap = run({ csp: `img-src ${Array(502).fill("x.example.com").join(" ")}` });
  eq(tokenCap.truncated_count, 2, "CSP token cap");
  const partial = run({ liveTlsDnsNames: [null, 42, {}, "good.example.com"], mxValues: "not an array" });
  eq(names(partial), ["good.example.com"], "malformed entries do not erase valid entries");
  eq(partial.rejected_count, 4, "invalid types counted");
  for (const bad of [undefined, null, 3, "x", [], { domain: {} }, { domain: "bad/root", sources: {} }, new Proxy({}, { get() { throw new Error("bad accessor"); } })]) {
    eq(api.extractHostnameCandidates(bad).candidates, [], "malformed outer input never throws");
  }
  const input = Object.freeze({ domain: "example.com", observedAt: "fixed", sources: Object.freeze({ liveTlsDnsNames: Object.freeze(["b.example.com", "a.example.com"]) }) });
  const before = JSON.stringify(input);
  eq(api.extractHostnameCandidates(input), api.extractHostnameCandidates(input), "same input same output");
  eq(JSON.stringify(input), before, "input remains immutable");
  eq(names(api.extractHostnameCandidates(input)), ["a.example.com", "b.example.com"], "candidate output sorted");
  const collector = api.createCandidateCollector({ domain: "example.com" });
  collector.add("a.example.com", "csp");
  const first = collector.result();
  first.candidates[0].sources.push("forged");
  eq(collector.result().candidates[0].sources, ["csp"], "results do not expose accumulator state");
  function assertEvidenceOnly(value) {
    if (!value || typeof value !== "object") return;
    for (const [key, child] of Object.entries(value)) {
      ok(!["observed", "active", "resolved"].includes(key), "no service or DNS state assertions");
      assertEvidenceOnly(child);
    }
  }
  assertEvidenceOnly(merged);
  return checks;
}

try {
  const api = await import(moduleUrl.href);
  let checks = fixtures(api);
  assert.ok(!/\b(?:fetch|connect)\s*\(|\b(?:import|require)\s*\([^)]*(?:node:|https?:)|from\s*["'](?:node:)?(?:net|tls|https?|dns|dgram)["']/.test(source), "production module has no network I/O"); checks++;
  assert.ok(!/Date\.now\s*\(|Math\.random\s*\(/.test(source), "no ambient time/randomness"); checks++;
  const mutations = [
    ["hostname === root || hostname.endsWith(\".\" + root)", "hostname.includes(root)", "scope weakened"],
    ["if (wildcard) return { kind: \"wildcard\", scope: hostname };", "if (wildcard) return { kind: \"candidate\", hostname };", "wildcard admitted"],
    ["names.get(item.hostname).add(source);", "names.set(item.hostname, new Set([source]));", "provenance overwritten"],
    ["maxCandidates: 200,", "maxCandidates: 201,", "candidate ceiling raised"],
    ["maxListItems: 500,", "maxListItems: 503,", "list ceiling bypassed"],
    ["new TextEncoder().encode(value).length > maxBytes", "false", "UTF8 byte limit removed"],
    ["if (!CSP_HOST_DIRECTIVES.has(name.toLowerCase())) continue;", "if (false) continue;", "report URL admitted"],
    ["if (!isCspHostSource(token)) return null;", "if (false) return null;", "invalid CSP authority repaired"],
  ];
  for (const [before, after, label] of mutations) {
    assert.equal(source.split(before).length, 2, `unique mutation anchor: ${label}`);
    const mutant = await import(`data:text/javascript;base64,${Buffer.from(source.replace(before, after)).toString("base64")}`);
    assert.throws(() => fixtures(mutant), assert.AssertionError, `fixture suite must reject ${label}`);
    checks++;
  }
  console.log(`${checks} checks passed (hostname candidates; ${mutations.length} in-memory mutants killed)`);
} catch (error) {
  console.error("FAIL hostname candidates:", error);
  process.exitCode = 1;
}
