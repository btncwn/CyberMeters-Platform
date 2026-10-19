#!/usr/bin/env node
// Local-only DNS preflight regression: real probe/modules and production call options.
import fs from "node:fs";
import path from "node:path";
import os from "node:os";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { makeSsrfSafeProbeFetch, makeReservedProbeFetch } from "../workers/scan-api/src/engines/reserved-probe.js";
import { probeAsset, runExposureModule, runAdminSurfaceModule } from "../workers/scan-api/src/engines/asset-intel.js";
import { dnsQuery } from "../workers/scan-api/src/engines/dns.js";
import { runSslModule } from "../workers/scan-api/src/engines/ssl-scan.js";
import { runHeadersModule } from "../workers/scan-api/src/engines/headers-scan.js";
import { runTechModule } from "../workers/scan-api/src/engines/tech-scan.js";
import { resolvePublicDnsTarget, resolvePublicDnsTargetWithRetry, STRICT_DNS_STATES } from "../workers/scan-api/src/lib/ssrf.js";

import { deriveAttackSurfaceSignalCompleteness, deriveRemovalObservation } from "../workers/scan-api/src/engines/attack-surface-signal-completeness.js";
import { computeSecurityPosture } from "../workers/scan-api/src/engines/posture-scoring.js";
import { buildPostureDiffEvents } from "../workers/scan-api/src/engines/posture-events.js";
import { buildScanQuality } from "../workers/scan-api/src/engines/scan-engine.js";
import { moduleCompletionGate } from "../workers/scan-api/src/engines/asm-cases.js";
import { resolveCyberMotDomainStates } from "../workers/scan-api/src/engines/cyber-mot-domains.js";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
let passed = 0, failed = 0;
const ok = (name, condition) => {
  if (condition) passed += 1;
  else { failed += 1; console.error(`FAIL ${name}`); }
};
const originalFetch = globalThis.fetch;
const host = "asset.example.test";
const target = `https://${host}/`;
const packet = (type, ips, name = host) => ({ Status: 0, TC: false,
  Question: [{ name: `${name}.`, type: type === "AAAA" ? 28 : 1 }],
  Answer: ips.map((data) => ({ name: `${name}.`, type: type === "AAAA" ? 28 : 1, data })) });
const publicDns = async (name, type) => packet(type, type === "A" ? ["93.184.216.34"] : [], name);
const privateDns = async (_name, type) => packet(type, type === "A" ? ["127.0.0.1"] : []);
const errorDns = async () => { throw new Error("synthetic DNS failure"); };
// DNS-JSON negative answers: RFC 2308 §2.2 / RFC 7129 §2.2. These
// fixtures are local producer-shape controls, not captured live DNS traffic.
function soaNodata(name, type, cname = false, rname = "hostmaster.example.test.") {
  return { Status: 0, TC: false, Question: [{ name: `${name}.`, type: type === "AAAA" ? 28 : 1 }],
    ...(cname ? { Answer: [{ name: `${name}.`, type: 5, data: "terminal.example.test." }] } : {}),
    Authority: [{ name: "example.test.", type: 6, TTL: 60,
      data: `ns.example.test. ${rname} 1 3600 600 86400 60` }] };
}
// Captured 19 Oct 2026 from cloudflare-dns.com: an IPv4-only apex whose AAAA
// NODATA SOA carries an escaped-dot mailbox RNAME (RFC 1035 §5.1, §8).
const tescoShaped = (soaData) => async (_name, type) => type === "A"
  ? { Status: 0, TC: false, Question: [{ name: "tesco.com", type: 1 }],
    Answer: [{ name: "tesco.com", type: 1, TTL: 17, data: "184.25.192.63" }] }
  : { Status: 0, TC: false, Question: [{ name: "tesco.com", type: 28 }],
    Authority: [{ name: "tesco.com", type: 6, TTL: 3164, data: soaData }] };
const TESCO_SOA = "pdns194.ultradns.com. web\\.admin.uk.tesco.com. 2015040710 86400 7200 2592000 3600";
const soaResolver = (cname = false) => async (name, type) => type === "A"
  ? (cname ? { ...packet(type, ["93.184.216.34"], name), Answer: [
    { name: `${name}.`, type: 5, data: "terminal.example.test." },
    { name: "terminal.example.test.", type: 1, data: "93.184.216.34" },
  ] } : publicDns(name, type)) : soaNodata(name, type, cname);
const observed = [];
function transport(resolver, redirectHost = null) {
  observed.length = 0;
  globalThis.fetch = async (url, opts = {}) => {
    const parsed = new URL(url);
    if (parsed.hostname === "cloudflare-dns.com") {
      return Response.json(await resolver(parsed.searchParams.get("name"), parsed.searchParams.get("type")));
    }
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
  // SOA RNAME is a mailbox: escapes are legal there and only there.
  const tesco = await resolvePublicDnsTarget("tesco.com", tescoShaped(TESCO_SOA));
  ok("TESCO_SHAPED_PUBLIC", tesco.state === STRICT_DNS_STATES.PUBLIC && tesco.addresses.join() === "184.25.192.63");
  for (const [label, rname] of [["plain", "webadmin.uk.tesco.com."], ["ddd", "web\\046admin.uk.tesco.com."],
    ["relative", "web\\.admin.uk.tesco.com"], ["single_label", "hostmaster."], ["escaped_backslash", "web\\\\.uk.tesco.com."]]) {
    const result = await resolvePublicDnsTarget("tesco.com", tescoShaped(TESCO_SOA.replace("web\\.admin.uk.tesco.com.", rname)));
    ok(`RNAME_ACCEPT_${label}`, result.state === STRICT_DNS_STATES.PUBLIC);
  }
  for (const [label, soa] of [
    ["six_fields", "pdns194.ultradns.com. web\\.admin.uk.tesco.com. 2015040710 86400 7200 2592000"],
    ["whitespace_rname", "pdns194.ultradns.com. web admin.uk.tesco.com. 2015040710 86400 7200 2592000 3600"],
    ["bad_serial", "pdns194.ultradns.com. web\\.admin.uk.tesco.com. 20150407x 86400 7200 2592000 3600"],
    ["ddd_over_255", "pdns194.ultradns.com. web\\256admin.uk.tesco.com. 2015040710 86400 7200 2592000 3600"],
    ["dangling_escape", "pdns194.ultradns.com. web\\ 2015040710 86400 7200 2592000 3600"],
    ["empty_label", "pdns194.ultradns.com. web..tesco.com. 2015040710 86400 7200 2592000 3600"],
    ["empty_rname_root", "pdns194.ultradns.com. . 2015040710 86400 7200 2592000 3600"],
    ["special_char", "pdns194.ultradns.com. web(admin).tesco.com. 2015040710 86400 7200 2592000 3600"],
    ["long_label", `pdns194.ultradns.com. ${"a".repeat(64)}.tesco.com. 2015040710 86400 7200 2592000 3600`],
    ["over_255", `pdns194.ultradns.com. ${Array(5).fill("a".repeat(60)).join(".")}.tesco.com. 2015040710 86400 7200 2592000 3600`],
    ["escaped_mname", "pdns194\\.x.ultradns.com. web\\.admin.uk.tesco.com. 2015040710 86400 7200 2592000 3600"],
  ]) {
    const result = await resolvePublicDnsTarget("tesco.com", tescoShaped(soa));
    ok(`RNAME_REJECT_${label}`, result.state === STRICT_DNS_STATES.UNAVAILABLE && result.reason === "incomplete_answer");
  }
  const tescoPrivate = await resolvePublicDnsTarget("tesco.com", async (name, type) => type === "A"
    ? { ...(await tescoShaped(TESCO_SOA)(name, type)), Answer: [{ name: "tesco.com", type: 1, data: "10.0.0.1" }] }
    : tescoShaped(TESCO_SOA)(name, type));
  ok("TESCO_SHAPED_PRIVATE_STILL_BLOCKED", tescoPrivate.state === STRICT_DNS_STATES.BLOCKED);
  // Free-scan target retry: transient first answers get exactly one more try.
  const flaky = (failFirst) => { let calls = 0; return { count: () => calls, resolver: async (name, type) => {
    calls += 1;
    if (calls === 1) return failFirst();
    return publicDns(name, type);
  } }; };
  for (const [label, failFirst] of [["resolver_error", () => { throw new Error("transient"); }],
    ["servfail", () => ({ Status: 2, TC: false })]]) {
    const dns = flaky(failFirst);
    const result = await resolvePublicDnsTargetWithRetry(host, dns.resolver);
    ok(`RETRY_${label}_RECOVERS`, result.state === STRICT_DNS_STATES.PUBLIC && result.attempts === 2 && dns.count() === 4);
  }
  for (const [label, resolver, state] of [["private", privateDns, STRICT_DNS_STATES.BLOCKED],
    ["no_address", (name, type) => soaNodata(name, type), STRICT_DNS_STATES.NO_ADDRESS],
    ["public", publicDns, STRICT_DNS_STATES.PUBLIC]]) {
    let calls = 0;
    const result = await resolvePublicDnsTargetWithRetry(host, async (name, type) => { calls += 1; return resolver(name, type); });
    ok(`RETRY_${label}_NOT_RETRIED`, result.state === state && calls === 2 && result.attempts === undefined);
  }
  {
    let calls = 0;
    const result = await resolvePublicDnsTargetWithRetry(host, async () => { calls += 1; throw new Error("down"); });
    ok("RETRY_PERSISTENT_BOUNDED", result.state === STRICT_DNS_STATES.UNAVAILABLE && result.reason === "resolver_error" && calls === 4);
  }
  {
    const aborted = new AbortController();
    aborted.abort("free_scan_deadline_exhausted");
    let calls = 0;
    const result = await resolvePublicDnsTargetWithRetry(host, async () => { calls += 1; throw new Error("down"); }, { signal: aborted.signal });
    ok("RETRY_NOT_AFTER_DEADLINE", result.state === STRICT_DNS_STATES.UNAVAILABLE && calls === 2);
  }
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
  ok("PROBE_SOA_BOTH_NODATA_ZERO_HTTP", observed.length === 0 && bothNodata.error?.code === "dns_no_address"
    && bothNodata.error.dns_stage === "initial" && bothNodata.error.dns_evidence?.families.AAAA.soa.zone === "example.test");

  for (const rcode of [0, 3]) {
    const negative = (name, type) => ({ ...soaNodata(name, type), Status: rcode });
    transport(negative);
    const allAbsent = await runExposureModule(host, [host], { cache: new Map() });
    const admin = runAdminSurfaceModule({ asset_exposure: allAbsent });
    const modules = { asset_exposure: allAbsent, admin_surface_detection: admin,
      dns: { resolution_assessed: true, resolves_any: true }, subdomains: { total: 1, subdomains: [host] } };
    const signals = deriveAttackSurfaceSignalCompleteness(modules).signals;
    ok(`NO_ADDRESS_${rcode}_SCAN_MEASUREMENT_COMPLETE`, buildScanQuality(modules).status === "complete");
    ok(`NO_ADDRESS_${rcode}_MEASUREMENT_COMPLETED`, observed.length === 0 && !allAbsent.incomplete
      && allAbsent.assets.every(a => a.probe_status === "not_applicable" && a.reachable === null && a.http_assessed === false));
    ok(`NO_ADDRESS_${rcode}_HTTP_NOT_HEALTHY`, admin.evidence_status === "not_assessed"
      && signals.http_https_service.state === "not_assessed" && signals.exposure_admin_surface.state === "not_assessed");
    // NXDOMAIN on the DNS signal and the probe's own preflight is a complete
    // removal negative, so a deleted name can progress to confirmed removal
    // instead of reading "not assessed" forever. NOERROR without an address
    // means the name still exists (mail or text records only): it is observed
    // and never progresses towards removal. Case closure stays blocked either
    // way (NO_CASE_VERIFICATION below).
    if (rcode === 3) {
      ok(`NO_ADDRESS_${rcode}_IS_COMPLETE_REMOVAL_NEGATIVE`, allAbsent.removal_observations.length > 0
        && allAbsent.removal_observations.every(row =>
          row.signal_states.dns_resolution.state === "absent"
          && row.signal_states.http_https_service.state === "not_observed"
          && row.signal_states.http_https_service.reason === "http_not_applicable_no_address"
          && deriveRemovalObservation(row.signal_states) === "not_observed"));
    } else {
      ok(`NO_ADDRESS_${rcode}_EXISTING_NAME_IS_OBSERVED`, allAbsent.removal_observations.length > 0
        && allAbsent.removal_observations.every(row =>
          row.signal_states.dns_resolution.state === "observed"
          && row.signal_states.dns_resolution.reason === "dns_name_without_address"
          && row.signal_states.http_https_service.state === "not_observed"
          && row.signal_states.http_https_service.reason === "http_not_applicable_no_address"
          && deriveRemovalObservation(row.signal_states) === "observed"));
    }
    ok(`NO_ADDRESS_${rcode}_NO_CASE_VERIFICATION`, !moduleCompletionGate(modules, { status: "complete" }).canVerify("asset_exposure")
      && !moduleCompletionGate(modules, { status: "complete" }).canVerify("admin_surface_detection"));
    const previous = { admin_surface_detection: { evidence_status: "issue_detected", services: [
      { hostname: host, product: "Admin", severity: "high", finding_type: "finding" },
    ] } };
    ok(`NO_ADDRESS_${rcode}_NO_RESOLVED_EVENT`, !buildPostureDiffEvents(host, previous, modules)
      .some(event => event.event_type === "exposed_service_resolved"));
    const posture = computeSecurityPosture({ brand_risks: {}, vendor_risk: {}, certificate_risks: {} }, { modules });
    ok(`NO_ADDRESS_${rcode}_NO_ADMIN_SCORE`, posture.admin_exposure.score === null);
    const mot = resolveCyberMotDomainStates({ modules, findings: [], scan_quality: { status: "complete" } });
    ok(`NO_ADDRESS_${rcode}_MOT_NOT_HEALTHY`, mot.find(d => d.domain_key === "attack_surface")?.state === "evidence_insufficient");
  }
  for (const [label, alter] of [
    ["question", p => ({ ...p, Question: [{ name: "wrong.example.test.", type: p.Question[0].type }] })],
    ["truncated", p => ({ ...p, TC: true })],
    ["weak_empty", p => ({ Status: 0, Answer: [] })],
    ["refused", p => ({ ...p, Status: 5 })],
    ["malformed_soa", p => ({ ...p, Authority: [{ ...p.Authority[0], data: "not an SOA" }] })],
    ["soa_missing", p => ({ ...p, Authority: [] })],
    ["soa_unrelated", p => ({ ...p, Authority: [{ ...p.Authority[0], name: "unrelated.test." }] })],
    ["servfail", p => ({ ...p, Status: 2 })],
    ["mixed_status", (p, type) => ({ ...p, Status: type === "A" ? 0 : 3 })],
    ["cname_loop", p => ({ ...p, Answer: [{ name: `${host}.`, type: 5, data: `${host}.` }] })],
  ]) {
    transport((name, type) => alter(soaNodata(name, type), type));
    const asset = await probeAsset(host);
    ok(`NO_ADDRESS_INVALID_${label}_PARTIAL`, observed.length === 0 && asset.probe_status === "not_executed");
  }
  for (const [label, resolver] of [
    ["nxdomain_public", (name, type) => type === "A" ? publicDns(name, type) : { ...soaNodata(name, type), Status: 3 }],
    ["cname_conflict", (name, type) => type === "A" ? publicDns(name, type) : soaNodata(name, type, true)],
  ]) {
    transport(resolver);
    const asset = await probeAsset(host);
    ok(`NO_ADDRESS_CONTRADICTION_${label}`, observed.length === 0 && asset.probe_status === "not_executed");
  }
  transport((name, type) => soaNodata(name, type, true));
  const absentAlias = await probeAsset(host);
  ok("NO_ADDRESS_CNAME_CHAIN_PROVEN", observed.length === 0 && absentAlias.probe_status === "not_applicable"
    && absentAlias.dns_evidence.families.A.terminal === "terminal.example.test");
  // A dangling CNAME (alias to a name with no address) is a takeover candidate,
  // not a removed asset: the alias record is still published, so it must read
  // observed and can never progress towards confirmed removal.
  {
    const danglingExposure = await runExposureModule(host, [host], { cache: new Map() });
    ok("NO_ADDRESS_DANGLING_CNAME_NEVER_REMOVAL_NEGATIVE", danglingExposure.removal_observations.length > 0
      && danglingExposure.removal_observations.every((row) =>
        row.signal_states.dns_resolution.state === "observed"
        && deriveRemovalObservation(row.signal_states) === "observed"));
  }
  const redirected = "redirect.example.test";
  transport((name, type) => name === redirected ? soaNodata(name, type) : publicDns(name, type), redirected);
  const redirectedAbsent = await probeAsset(host);
  ok("NO_ADDRESS_REDIRECT_NOT_NA", observed.length > 0 && observed.every(c => c.hostname === host)
    && redirectedAbsent.probe_status === "not_executed");

  const absentHost = "absent.example.test";
  transport((name, type) => name === absentHost ? soaNodata(name, type) : publicDns(name, type));
  const mixed = await runExposureModule(host, [host, absentHost], { cache: new Map() });
  const mixedAdmin = runAdminSurfaceModule({ asset_exposure: mixed });
  const mixedSignals = deriveAttackSurfaceSignalCompleteness({ asset_exposure: mixed, admin_surface_detection: mixedAdmin }).signals;
  ok("NO_ADDRESS_MIXED_REAL_OBSERVATION_RETAINED", !mixed.incomplete && mixed.reachable > 0
    && mixedSignals.http_https_service.state === "observed" && mixedSignals.http_https_service.limitations.length > 0
    && mixedAdmin.evidence_status === "not_assessed");
  mixed.assets.find(a => a.reachable === true).title = "Grafana";
  const mixedFinding = runAdminSurfaceModule({ asset_exposure: mixed });
  ok("NO_ADDRESS_MIXED_REAL_FINDING_RETAINED", mixedFinding.evidence_status === "issue_detected" && mixedFinding.total > 0);
  transport(publicDns);
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
        "subOpTelemetry", "certificateNowMs", "moduleSignal", `return (${expression});`);
      for (const cname of [false, true]) {
        transport(soaResolver(cname));
        const options = build(dnsQuery, new Map(), null, undefined, null, false, undefined, Date.now(), undefined);
        await functions[name](host, options);
        ok(`CALLER_${file}_${name}_SOA_${cname ? "CNAME" : "OMITTED"}_PUBLIC`, observed.length > 0);
      }
      transport(async (name, type) => type === "A" ? publicDns(name, type)
        : soaNodata(name, type, false, "web\\.admin.example.test."));
      await functions[name](host, build(dnsQuery, new Map(), null, undefined, null, false, undefined, Date.now(), undefined));
      ok(`CALLER_${file}_${name}_ESCAPED_RNAME_PUBLIC`, observed.length > 0);
      for (const [state, resolver] of [["error", errorDns], ["private", privateDns], ["public", publicDns]]) {
        transport(resolver);
        const dnsCache = new Map();
        const options = build(dnsQuery, dnsCache, null, undefined, null, false, undefined, Date.now(), undefined);
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
        const options = build(dnsQuery, new Map(), null, undefined, null, false, undefined, Date.now(), undefined);
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
// CI uses the standard argument-free validator carrier; include mutation proof
// by default. Only isolated mutant children select the behavioral-only mode.
if (!process.argv.includes("--behavior-only") && failed === 0) {
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
    { id: "SOA_RNAME_AS_HOSTNAME", file: "lib/ssrf.js",
      before: "validSoaMailbox(fields[1])", after: "validCname(fields[1])",
      expected: "TESCO_SHAPED_PUBLIC" },
    { id: "SOA_RNAME_UNCHECKED", file: "lib/ssrf.js",
      before: "validSoaMailbox(fields[1])", after: "true",
      expected: "RNAME_REJECT_ddd_over_255" },
    { id: "TARGET_RETRY_DISABLED", file: "lib/ssrf.js",
      before: "  const second = await resolvePublicDnsTarget(domain, dnsQuery, opts);",
      after: "  const second = first;",
      expected: "RETRY_resolver_error_RECOVERS" },
    { id: "TARGET_RETRY_UNBOUNDED_REASONS", file: "lib/ssrf.js",
      before: "  if (first.state !== STRICT_DNS_STATES.UNAVAILABLE || !TRANSIENT_DNS_TARGET_REASONS.has(first.reason)",
      after: "  if (first.state === STRICT_DNS_STATES.PUBLIC",
      expected: "RETRY_private_NOT_RETRIED" },
    { id: "SOA_AUTHORITY_UNCHECKED", file: "lib/ssrf.js",
      before: "if (terminal !== zone && !terminal.endsWith(`.${zone}`)) return false;",
      after: "if (false) return false;",
      expected: "PROBE_SOA_unrelated_ZERO_HTTP" },
    { id: "NO_ADDRESS_PROOF_BYPASS", file: "lib/ssrf.js",
      before: "negativeA.status === negativeAAAA.status", after: "true",
      expected: "NO_ADDRESS_INVALID_mixed_status_PARTIAL" },
    { id: "NO_ADDRESS_ADMIN_FALSE_HEALTHY", file: "engines/asset-intel.js",
      before: 'exposureAssets.some((asset) => ["not_applicable", "target_unavailable"].includes(asset.probe_status))',
      after: 'exposureAssets.some((asset) => asset.probe_status === "target_unavailable")',
      expected: "NO_ADDRESS_0_HTTP_NOT_HEALTHY" },
    { id: "NO_ADDRESS_CASE_GATE_REMOVED", file: "engines/asm-cases.js",
      before: 'incomplete.add("asset_exposure");', after: 'void 0;',
      expected: "NO_ADDRESS_0_NO_CASE_VERIFICATION" },
    { id: "SOA_QUESTION_UNCHECKED", file: "lib/ssrf.js",
      before: "|| normalize(packet.Question[0]?.name) !== normalize(host)\n      || !Array.isArray(answers)", after: "|| false\n      || !Array.isArray(answers)",
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
    fs.cpSync(path.join(root, "workers/network-probe/src"), path.join(directory, "workers/network-probe/src"), { recursive: true });
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
        const child = spawnSync(process.execPath, ["scripts/validate-scan-dns-preflight.js", "--behavior-only"], {
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
