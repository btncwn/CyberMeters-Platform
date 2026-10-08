#!/usr/bin/env node
// Local-only DNS preflight regression: real probe/modules and production call options.
import fs from "node:fs";
import path from "node:path";
import os from "node:os";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { makeSsrfSafeProbeFetch, makeReservedProbeFetch } from "../workers/scan-api/src/engines/reserved-probe.js";
import { probeAsset, runExposureModule } from "../workers/scan-api/src/engines/asset-intel.js";
import { dnsQuery } from "../workers/scan-api/src/engines/dns.js";
import { runSslModule } from "../workers/scan-api/src/engines/ssl-scan.js";
import { runHeadersModule } from "../workers/scan-api/src/engines/headers-scan.js";
import { runTechModule } from "../workers/scan-api/src/engines/tech-scan.js";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
let passed = 0, failed = 0;
const ok = (name, condition) => {
  if (condition) passed += 1;
  else { failed += 1; console.error(`FAIL ${name}`); }
};
const originalFetch = globalThis.fetch;
const host = "asset.example.test";
const target = `https://${host}/`;
const packet = (type, ips) => ({ Status: 0, Answer: ips.map((data) => ({ type: type === "AAAA" ? 28 : 1, data })) });
const publicDns = async (_name, type) => packet(type, type === "A" ? ["93.184.216.34"] : []);
const privateDns = async (_name, type) => packet(type, type === "A" ? ["127.0.0.1"] : []);
const errorDns = async () => { throw new Error("synthetic DNS failure"); };
// DNS-JSON negative answers: RFC 2308 §2.2 / RFC 7129 §2.2. These
// fixtures are local producer-shape controls, not captured live DNS traffic.
function soaNodata(name, type, cname = false) {
  return { Status: 0, TC: false, Question: [{ name: `${name}.`, type: type === "AAAA" ? 28 : 1 }],
    ...(cname ? { Answer: [{ name: `${name}.`, type: 5, data: "terminal.example.test." }] } : {}),
    Authority: [{ name: "example.test.", type: 6, TTL: 60,
      data: "ns.example.test. hostmaster.example.test. 1 3600 600 86400 60" }] };
}
const soaResolver = (cname = false) => async (name, type) => type === "A"
  ? publicDns(name, type) : soaNodata(name, type, cname);
const observed = [];
function transport(resolver, redirectHost = null) {
  observed.length = 0;
  globalThis.fetch = async (url, opts = {}) => {
    const parsed = new URL(url);
    if (parsed.hostname === "cloudflare-dns.com") {
      return Response.json(await resolver(parsed.searchParams.get("name"), parsed.searchParams.get("type")));
    }
    if (["crt.sh", "api.certspotter.com"].includes(parsed.hostname)) return Response.json([]);
    // No fallback to native fetch: every outbound operation is synthetic.
    observed.push({ hostname: parsed.hostname, redirect: opts.redirect });
    if (redirectHost && parsed.hostname !== redirectHost) {
      return new Response(null, { status: 302, headers: { location: `https://${redirectHost}/` } });
    }
    return new Response("<title>synthetic</title>", { headers: { "content-type": "text/html", server: "synthetic" } });
  };
}
async function caught(call) { try { return { value: await call() }; } catch (error) { return { error }; } }

try {
  for (const [name, resolver] of [
    ["error", errorDns], ["missing", undefined],
    ["empty", async () => ({ Status: 0, Answer: [] })],
    ["incomplete", async (_name, type) => type === "A" ? packet(type, ["93.184.216.34"]) : null],
  ]) {
    transport(publicDns);
    const result = await caught(() => makeSsrfSafeProbeFetch({ resolver })(target));
    ok(`PROBE_${name}_ZERO_HTTP`, observed.length === 0);
    ok(`PROBE_${name}_UNAVAILABLE`, result.error?.code === "dns_resolution_unavailable");
  }
  const negativeBase = soaNodata(host, "AAAA");
  for (const [name, invalid] of [
    ["bare", { Status: 0 }],
    ["missing_question", { ...negativeBase, Question: [] }],
    ["wrong_question", { ...negativeBase, Question: [{ name: "other.example.test.", type: 28 }] }],
    ["wrong_family", { ...negativeBase, Question: [{ name: `${host}.`, type: 1 }] }],
    ["referral", { ...negativeBase, Authority: [{ name: "example.test.", type: 2, data: "ns.example.test." }] }],
    ["unrelated", { ...negativeBase, Authority: [{ ...negativeBase.Authority[0], name: "other.test." }] }],
    ["malformed", { ...negativeBase, Authority: [{ ...negativeBase.Authority[0], data: "not an SOA" }] }],
    ["truncated", { ...negativeBase, TC: true }],
    ["servfail", { ...negativeBase, Status: 2 }],
    ["null_answer", { ...negativeBase, Answer: null }],
    ["wrong_cname_owner", { ...soaNodata(host, "AAAA", true), Answer: [{ name: "unrelated.example.test.", type: 5, data: "terminal.example.test." }] }],
    ["cname_loop", { ...soaNodata(host, "AAAA", true), Answer: [{ name: `${host}.`, type: 5, data: `${host}.` }] }],
  ]) {
    transport(publicDns);
    const resolver = async (name, type) => type === "A" ? publicDns(name, type) : invalid;
    const result = await caught(() => makeSsrfSafeProbeFetch({ resolver })(target));
    ok(`PROBE_SOA_${name}_ZERO_HTTP`, observed.length === 0 && result.error?.code === "dns_resolution_unavailable");
  }
  transport(publicDns);
  const bothNodata = await caught(() => makeSsrfSafeProbeFetch({ resolver: (name, type) => soaNodata(name, type) })(target));
  ok("PROBE_SOA_BOTH_NODATA_UNAVAILABLE", observed.length === 0 && bothNodata.error?.code === "dns_resolution_unavailable");
  const negativeWithPrivate = await makeSsrfSafeProbeFetch({ resolver: async (name, type) =>
    type === "A" ? privateDns(name, type) : soaNodata(name, type) })(target);
  ok("PROBE_SOA_PRIVATE_SIBLING_BLOCKED", negativeWithPrivate === null && observed.length === 0);
  for (const cname of [false, true]) {
    for (const reserved of [false, true]) {
      transport(soaResolver(cname));
      const options = reserved ? { fetcher: makeReservedProbeFetch({ cache: new Map() }) } : {};
      const asset = await probeAsset(host, options);
      ok(`PROBE_SOA_${cname ? "CNAME" : "OMITTED"}_${reserved ? "RESERVED" : "DEFAULT"}_PUBLIC`,
        asset.reachable === true && observed.length === 1);
    }
  }
  for (const error of [new Error("Too many subrequests by single Worker invocation."),
    Object.assign(new Error("synthetic budget"), { code: "scan_subrequest_budget_exhausted" }),
    new DOMException("synthetic cancellation", "AbortError")]) {
    transport(publicDns);
    const result = await caught(() => makeSsrfSafeProbeFetch({ resolver: async () => { throw error; } })(target));
    ok(`PROBE_CONTROL_${error.code || error.name}_PRESERVED`, observed.length === 0 && result.error === error);
  }
  transport(publicDns);
  const allowed = await makeSsrfSafeProbeFetch({ resolver: publicDns })(target);
  ok("PROBE_PUBLIC_ALLOWED", allowed?.status === 200 && observed.length === 1 && observed[0].redirect === "manual");
  transport(publicDns);
  ok("PROBE_PRIVATE_ZERO_HTTP", (await makeSsrfSafeProbeFetch({ resolver: privateDns })(target)) === null && observed.length === 0);
  ok("PROBE_LITERAL_ZERO_HTTP", (await makeSsrfSafeProbeFetch({ resolver: publicDns })("http://127.0.0.1/")) === null && observed.length === 0);

  for (const [name, resolver] of [["private", privateDns], ["error", errorDns]]) {
    const next = "redirect.example.test";
    const perHost = (name, type) => name === next ? resolver(name, type) : publicDns(name, type);
    transport(perHost, next);
    const result = await caught(() => makeSsrfSafeProbeFetch({ resolver: perHost })(target));
    ok(`PROBE_REDIRECT_${name}_NOT_FETCHED`, observed.length === 1 && observed[0].hostname === host);
    ok(`PROBE_REDIRECT_${name}_REFUSED`, name === "private" ? result.value === null : result.error?.code === "dns_resolution_unavailable");
  }
  for (const [name, fetcher] of [["default", null], ["reserved", makeReservedProbeFetch({ cache: new Map() })]]) {
    transport(errorDns);
    const asset = await probeAsset(host, fetcher ? { fetcher } : {});
    ok(`ASSET_${name}_DNS_UNASSESSED`, observed.length === 0 && asset.reachable === null
      && asset.probe_status === "not_executed" && asset.reason === "dns_resolution_unavailable");
  }
  transport(errorDns);
  const exposure = await runExposureModule(host, [host], { cache: new Map() });
  ok("EXPOSURE_DNS_FAILURE_INCOMPLETE", observed.length === 0 && exposure.incomplete === true
    && exposure.incomplete_reason === "dns_resolution_unavailable");
  ok("EXPOSURE_DNS_FAILURE_NO_REMOVAL_PROOF", exposure.removal_observations.length > 0
    && exposure.removal_observations.every((row) => row.signal_states.http_https_service.state === "not_assessed"));

  // Evaluate the exact argument expressions at all six production call sites,
  // then run the real modules with those options and the real dnsQuery leaf.
  // This isolates HTTP-module wiring without stubbing their preflight or fetches.
  const functions = { runSslModule, runHeadersModule, runTechModule };
  for (const file of ["scan-engine.js", "reserved-scan.js"]) {
    const source = fs.readFileSync(path.join(root, "workers/scan-api/src/engines", file), "utf8");
    const calls = [...source.matchAll(/(runSslModule|runHeadersModule|runTechModule)\(domain, (\{[^\n]+?\})\)/g)];
    ok(`CALLER_${file}_THREE_CALLS`, calls.length === 3);
    ok(`CALLER_${file}_IMPORTS_REAL_DNS`, /import \{[^}]*\bdnsQuery\b[^}]*\} from "\.\/dns\.js"/.test(source));
    for (const [, name, expression] of calls) {
      const build = new Function("dnsQuery", "dnsCache", "accounting", "signal", "remainingMs", "durableInvocation",
        "ctCache", "sharedCtCache", "subOpTelemetry", "certificateNowMs", "consumerSignal", `return (${expression});`);
      for (const cname of [false, true]) {
        transport(soaResolver(cname));
        const options = build(dnsQuery, new Map(), null, undefined, null, false, undefined, undefined, undefined, Date.now(), undefined);
        await functions[name](host, options);
        ok(`CALLER_${file}_${name}_SOA_${cname ? "CNAME" : "OMITTED"}_PUBLIC`, observed.length > 0);
      }
      for (const [state, resolver] of [["error", errorDns], ["private", privateDns], ["public", publicDns]]) {
        transport(resolver);
        const dnsCache = new Map();
        const options = build(dnsQuery, dnsCache, null, undefined, null, false, undefined, undefined, undefined, Date.now(), undefined);
        ok(`CALLER_${file}_${name}_RESOLVER_CACHE_${state}`, options.dnsResolver === dnsQuery && options.dnsCache === dnsCache);
        const result = await functions[name](host, options);
        ok(`CALLER_${file}_${name}_${state}_HTTP`, state === "public" ? observed.length > 0 : observed.length === 0);
        if (state !== "public") {
          const inconclusive = name === "runSslModule" ? result.https_available === null
            : name === "runHeadersModule" ? result.accessible === false && result.incomplete === true
            : result.incomplete === true;
          ok(`CALLER_${file}_${name}_${state}_INCONCLUSIVE`, inconclusive);
        }
        ok(`CALLER_${file}_${name}_${state}_MANUAL`, observed.every((call) => call.redirect === "manual"));
      }
      for (const [state, resolver] of [["private", privateDns], ["error", errorDns], ["public", publicDns]]) {
        const next = "redirect.example.test";
        transport((name, type) => name === next ? resolver(name, type) : publicDns(name, type), next);
        const options = build(dnsQuery, new Map(), null, undefined, null, false, undefined, undefined, undefined, Date.now(), undefined);
        await functions[name](host, options);
        ok(`CALLER_${file}_${name}_REDIRECT_${state}`, state === "public"
          ? (name === "runSslModule" || observed.some((call) => call.hostname === next))
          : !observed.some((call) => call.hostname === next));
      }
    }
  }
} finally { globalThis.fetch = originalFetch; }
// Named mutants run only in disposable copies. Syntax/import failures never
// count as kills: each child must finish and report the intended assertion.
if (process.argv.includes("--mutations") && failed === 0) {
  const worker = path.join(root, "workers/scan-api");
  const mutants = [];
  for (const file of ["scan-engine.js", "reserved-scan.js"]) {
    for (const name of ["runSslModule", "runHeadersModule", "runTechModule"]) {
      mutants.push({ id: `${file}_${name}_DNS_REMOVED`, file: `engines/${file}`,
        before: `${name}(domain, { dnsResolver: dnsQuery, dnsCache,`,
        after: `${name}(domain, { dnsCache,`, expected: `CALLER_${file}_${name}_private_HTTP` });
    }
  }
  mutants.push(
    { id: "SOA_NODATA_DISABLED", file: "lib/ssrf.js",
      before: "function hasAuthoritativeNodata(packet, family, host, answers) {",
      after: "function hasAuthoritativeNodata(packet, family, host, answers) { return false;",
      expected: "PROBE_SOA_OMITTED_DEFAULT_PUBLIC" },
    { id: "SOA_AUTHORITY_UNCHECKED", file: "lib/ssrf.js",
      before: "return Array.isArray(packet.Authority) && packet.Authority.some((record) => {",
      after: "return true || Array.isArray(packet.Authority) && packet.Authority.some((record) => {",
      expected: "PROBE_SOA_unrelated_ZERO_HTTP" },
    { id: "SOA_QUESTION_UNCHECKED", file: "lib/ssrf.js",
      before: "normalize(packet.Question[0]?.name) !== normalize(host)", after: "false",
      expected: "PROBE_SOA_wrong_question_ZERO_HTTP" },
    { id: "PROBE_UNAVAILABLE_ALLOWED", file: "engines/reserved-probe.js",
      before: "if (resolution.state !== STRICT_DNS_STATES.PUBLIC) {", after: "if (false) {",
      expected: "PROBE_error_ZERO_HTTP" },
    { id: "PROBE_REDIRECT_DNS_SKIPPED", file: "engines/reserved-probe.js",
      before: "const resolution = await resolvePublicDnsTarget(hostname, resolver, {",
      after: "const resolution = hop > 0 ? { state: STRICT_DNS_STATES.PUBLIC } : await resolvePublicDnsTarget(hostname, resolver, {",
      expected: "PROBE_REDIRECT_private_NOT_FETCHED" },
    { id: "ASSET_DNS_FAILURE_FALSE_NEGATIVE", file: "engines/asset-intel.js",
      before: 'else if (err?.code === "dns_resolution_unavailable") dnsUnavailable = true;',
      after: 'else if (err?.code === "dns_resolution_unavailable") void err;',
      expected: "ASSET_default_DNS_UNASSESSED" },
  );
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "scan-dns-mutants-"));
  try {
    fs.mkdirSync(path.join(directory, "workers/scan-api"), { recursive: true });
    fs.mkdirSync(path.join(directory, "scripts"));
    fs.cpSync(path.join(worker, "src"), path.join(directory, "workers/scan-api/src"), { recursive: true });
    fs.cpSync(path.join(root, "shared"), path.join(directory, "shared"), { recursive: true });
    fs.copyFileSync(path.join(worker, "package.json"), path.join(directory, "workers/scan-api/package.json"));
    fs.symlinkSync(path.join(worker, "node_modules"), path.join(directory, "workers/scan-api/node_modules"), "dir");
    fs.copyFileSync(fileURLToPath(import.meta.url), path.join(directory, "scripts/validate-scan-dns-preflight.js"));
    for (const mutant of [{ id: "COMMENT_CONTROL", file: "engines/reserved-probe.js", before: "export const RESERVED_MAX_REDIRECT_HOPS", after: "// inert mutation control\nexport const RESERVED_MAX_REDIRECT_HOPS", expected: null }, ...mutants]) {
      const file = path.join(directory, "workers/scan-api/src", mutant.file);
      const original = fs.readFileSync(file, "utf8");
      if (original.split(mutant.before).length !== 2) { ok(`MUTANT_${mutant.id}_ANCHOR`, false); continue; }
      fs.writeFileSync(file, original.replace(mutant.before, mutant.after));
      try {
        const child = spawnSync(process.execPath, ["scripts/validate-scan-dns-preflight.js"], {
          cwd: directory, encoding: "utf8", timeout: 30_000, maxBuffer: 1024 * 1024,
        });
        const output = child.stdout + child.stderr;
        ok(`MUTANT_${mutant.id}`, mutant.expected === null
          ? child.status === 0 && /Scan DNS preflight: \d+ passed, 0 failed/.test(output)
          : child.status === 1 && /Scan DNS preflight: \d+ passed, [1-9]\d* failed/.test(output)
            && output.includes(`FAIL ${mutant.expected}\n`));
      } finally { fs.writeFileSync(file, original); }
    }
  } finally { fs.rmSync(directory, { recursive: true, force: true }); }
}
console.log(`Scan DNS preflight: ${passed} passed, ${failed} failed`);
if (failed) process.exit(1);
