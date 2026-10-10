#!/usr/bin/env node
//
// Exposure-probe honesty proof.
//
// Trust regression guard for the subrequest-budget exhaustion defect: when a
// Cloudflare Worker runs out of its per-invocation subrequest budget, every
// remaining fetch throws "Too many subrequests by single Worker invocation." The
// old probeAsset swallowed this into reachable:false, which reads to a customer as
// "confirmed unreachable / no exposed asset" — a falsely-clean result, and it let
// managed-case verification resolve off a scan that never actually re-checked.
//
// This proves the honest semantics end-to-end (probe → module → scan_quality →
// managed-case gate) without a DB: an exhausted probe is not-executed (reachable:null),
// the module flags incomplete, scan_quality is forced partial, and the managed-case
// completeness gate defers. Genuine failures and successes are unchanged. Node 24+.
// CI-blocking.
//
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const eng = (f) => import(pathToFileURL(path.join(root, "workers", "scan-api", "src", "engines", f)).href);

const { probeAsset, runExposureModule } = await eng("asset-intel.js");
const { buildScanQuality }              = await eng("scan-engine.js");
const { moduleCompletionGate }          = await eng("asm-cases.js");

let pass = 0, fail = 0;
const ok = (name, cond) => { cond ? pass++ : fail++; if (!cond) console.log("FAIL " + name); };

const realFetch = globalThis.fetch;
// HTTP fixtures first provide a valid public DNS preflight. DNS-specific
// fixtures opt out so resolver failures remain independently exercised.
const withPublicDns = (fn, dnsFixture = false) => fn === realFetch || dnsFixture ? fn : async (value, ...args) => {
  const url = new URL(String(value));
  if (["cloudflare-dns.com", "dns.google"].includes(url.hostname)) {
    const answer = url.searchParams.get("type") === "A" ? [{ type: 1, data: "93.184.216.34" }] : [];
    return new Response(JSON.stringify({ Status: 0, Answer: answer }), { status: 200 });
  }
  return fn(value, ...args);
};
const setFetch = (fn, dnsFixture = false) => { globalThis.fetch = withPublicDns(fn, dnsFixture); };
const html200 = () => new Response("<title>Admin</title>", { status: 200, headers: { "content-type": "text/html" } });
const budgetError = () => { throw new Error("Too many subrequests by single Worker invocation. To configure this limit, refer to https://developers.cloudflare.com/…"); };
const networkError = () => { throw new TypeError("network error: connection refused"); };

// ── 1. probeAsset — genuine network failure still produces reachable:false ─────
setFetch(networkError);
let a = await probeAsset("down.example");
ok("genuine failure → reachable:false", a.reachable === false);
ok("genuine failure → NOT flagged not_executed", a.probe_status === undefined && a.reason === undefined);
ok("genuine failure → status null", a.status === null);

// ── 2. probeAsset — subrequest exhaustion → reachable:null / not_executed ──────
setFetch(budgetError);
a = await probeAsset("starved.example");
ok("exhaustion → reachable:null (NOT false)", a.reachable === null);
ok("exhaustion → probe_status not_executed", a.probe_status === "not_executed");
ok("exhaustion → reason subrequest_budget_exhausted", a.reason === "subrequest_budget_exhausted");

// ── 3. probeAsset — ordinary success unchanged (no new fields) ────────────────
setFetch(html200);
a = await probeAsset("up.example");
ok("success → reachable:true", a.reachable === true && a.status === 200);
ok("success → no probe_status/reason leak (shape unchanged)", a.probe_status === undefined && a.reason === undefined);

// ── 4. runExposureModule — all starved → incomplete + notice, reachable 0 ─────
setFetch(budgetError);
let mod = await runExposureModule("example.com", ["a.example.com", "b.example.com"]);
ok("module (all starved) → incomplete:true", mod.incomplete === true);
ok("module → incomplete_reason subrequest_budget_exhausted", mod.incomplete_reason === "subrequest_budget_exhausted");
ok("module → customer-safe notice, no raw error text", typeof mod.notice === "string" && /could not complete/i.test(mod.notice) && !/subrequest/i.test(mod.notice));
ok("module → reachable 0 but NOT a clean verified result (incomplete set)", mod.reachable === 0 && mod.incomplete === true);

// ── 5. runExposureModule — genuine failures → NOT incomplete ──────────────────
setFetch(networkError);
mod = await runExposureModule("example.com", ["a.example.com", "b.example.com"]);
ok("module (genuine fail) → not flagged incomplete", !mod.incomplete);
ok("module (genuine fail) → reachable 0", mod.reachable === 0);

// ── 6. runExposureModule — success unchanged ──────────────────────────────────
setFetch(html200);
mod = await runExposureModule("example.com", ["a.example.com"]);
ok("module (success) → reachable > 0, not incomplete", mod.reachable === 1 && !mod.incomplete);

globalThis.fetch = realFetch;

// ── 7. buildScanQuality — incomplete exposure forces partial + skipped ────────
const qPartial = buildScanQuality({
  dns: { resolves: true }, ssl: {}, headers: { accessible: true }, email_security: {},
  asset_exposure: { checked: 5, reachable: 0, incomplete: true, incomplete_reason: "subrequest_budget_exhausted" },
});
ok("scan_quality → partial when exposure incomplete", qPartial.status === "partial");
ok("scan_quality → asset_exposure listed as skipped", qPartial.modules_skipped.includes("asset_exposure"));

const qComplete = buildScanQuality({
  dns: { resolves: true }, ssl: {}, headers: { accessible: true }, email_security: {},
  asset_exposure: { checked: 5, reachable: 2 },   // genuine, complete
});
ok("scan_quality → NOT partial on a genuine complete exposure", qComplete.status !== "partial");

// ── 8. Managed-case completeness gate — defer when exposure did not run ────────
const modulesIncomplete = { asset_exposure: { checked: 5, reachable: 0, incomplete: true } };
const gateIncomplete = moduleCompletionGate(modulesIncomplete, qPartial);
ok("gate → cannot verify an asset_exposure case on an incomplete scan (deferred)",
   gateIncomplete.canVerify("asset_exposure") === false);
ok("gate → scanPartial true (blocks resolution broadly)", gateIncomplete.scanPartial === true);

// zero exposed assets must NOT read as verified-clean when probes did not run:
ok("gate → absence of finding is NOT resolvable when exposure incomplete",
   gateIncomplete.canVerify("asset_exposure") === false);

const gateComplete = moduleCompletionGate(
  { asset_exposure: { checked: 5, reachable: 2 } },
  qComplete,
);
ok("gate → CAN verify on a genuine complete scan (happy path unchanged)",
   gateComplete.canVerify("asset_exposure") === true);

// ── 9. Discovery reaches the high-risk names ──────────────────────────────────
// The production (legacy-capacity) path brute-forces a curated wordlist and
// probes only the first 50 exposure targets. A discovered admin/VPN host must
// never be cut off by ordinary CT names, and the wordlist must cover every
// critical prefix the reserved path treats as mandatory or optional.
{
  const {
    BRUTE_FORCE_WORDLIST, BRUTEFORCE_MAX_NAMES, HIGH_VALUE_EXPOSURE_LABELS,
    HIGH_VALUE_PRIORITY_SLOTS, prioritizeExposureTargets,
  } = await eng("subdomains-scan.js");
  const { CRITICAL_PREFIXES_MANDATORY, CRITICAL_PREFIXES_OPTIONAL } = await eng("scan-budget.js");
  const fs = await import("node:fs");

  ok("wordlist: exactly BRUTEFORCE_MAX_NAMES unique names",
    BRUTE_FORCE_WORDLIST.length === BRUTEFORCE_MAX_NAMES && new Set(BRUTE_FORCE_WORDLIST).size === BRUTEFORCE_MAX_NAMES);
  ok("wordlist: covers every mandatory and optional critical prefix",
    [...CRITICAL_PREFIXES_MANDATORY, ...CRITICAL_PREFIXES_OPTIONAL].every((p) => BRUTE_FORCE_WORDLIST.includes(p)));
  ok("high-value labels: every critical prefix is prioritised",
    [...CRITICAL_PREFIXES_MANDATORY, ...CRITICAL_PREFIXES_OPTIONAL].every((p) => HIGH_VALUE_EXPOSURE_LABELS.includes(p)));

  const ct = Array.from({ length: 60 }, (_, i) => `h${i}.example.com`);
  const known = ["h59.example.com", "legacy.example.com"];
  const discovered = [...ct, "ADMIN.example.com", "vpn.example.com", "admin.example.com", "api.eu.example.com", "admin.other.org"];
  const ordered = prioritizeExposureTargets("example.com", { knownHosts: known, discoveredHosts: discovered });
  ok("priority: high-value hosts first (admin, vpn, nested api)",
    JSON.stringify(ordered.slice(0, 3)) === JSON.stringify(["admin.example.com", "vpn.example.com", "api.eu.example.com"]));
  ok("priority: known assets follow the high-value block",
    JSON.stringify(ordered.slice(3, 5)) === JSON.stringify(["h59.example.com", "legacy.example.com"]));
  ok("priority: a host outside the scanned domain is never treated as high-value",
    ordered.indexOf("admin.other.org") > 4);
  const expectedSet = new Set([...known, ...discovered].map((h) => h.toLowerCase()));
  ok("priority: nothing added, dropped or duplicated — order only",
    ordered.length === expectedSet.size && ordered.every((h) => expectedSet.has(h)));
  ok("priority: admin and vpn land inside the 50-target probe cap even with 60 CT names first",
    ordered.slice(0, 50).includes("admin.example.com") && ordered.slice(0, 50).includes("vpn.example.com"));

  const many = Array.from({ length: 40 }, (_, i) => `api.r${i}.example.com`);
  const capped = prioritizeExposureTargets("example.com", { knownHosts: ["keep.example.com"], discoveredHosts: many });
  ok("priority: high-value block is bounded so known assets keep slots",
    capped.indexOf("keep.example.com") === HIGH_VALUE_PRIORITY_SLOTS);

  // End to end through the real exposure module: the admin host is probed.
  const plain = [...ct, "admin.example.com"];
  globalThis.fetch = withPublicDns(async () => new Response("<title>ok</title>", { status: 200, headers: { "content-type": "text/html" } }));
  const before = await runExposureModule("example.com", [...new Set(plain)]);
  const after = await runExposureModule("example.com", prioritizeExposureTargets("example.com", { discoveredHosts: plain }));
  globalThis.fetch = realFetch;
  ok("module: discovery order alone used to leave admin unprobed (fixture is meaningful)",
    !before.assets.some((a) => a.host === "admin.example.com"));
  ok("module: prioritised order probes the admin host within the cap",
    after.assets.some((a) => a.host === "admin.example.com") && after.checked === 50);

  const engineSrc = fs.readFileSync(path.join(root, "workers/scan-api/src/engines/scan-engine.js"), "utf8");
  ok("wiring: production exposure targets come from prioritizeExposureTargets",
    /const exposureTargets = prioritizeExposureTargets\(domain, \{\s*knownHosts: knownAssetHosts,\s*discoveredHosts: mergedSubdomainItems,\s*\}\);/.test(engineSrc)
      && /runExposureModule\(domain, exposureTargets,/.test(engineSrc));
}

// ── 10. First-party references reach discovery ───────────────────────────────
// A wildcard certificate keeps hosts out of CT and a word list only guesses
// common names. SRV records and the site's own links name the rest — without
// any third-party data source and without asserting anything about third
// parties: only names under the scanned domain are kept.
{
  const {
    SRV_DISCOVERY_LABELS, srvTargetsUnder, runBruteforceModule, withReferencedHostnames,
    BRUTEFORCE_MAX_NAMES,
  } = await eng("subdomains-scan.js");
  const { LINKED_HOST_LIMITS, linkedHostnamesUnder, runTechModule } = await eng("tech-scan.js");
  const fs = await import("node:fs");
  const doh = (answers) => new Response(JSON.stringify({ Status: 0, Answer: answers }), { status: 200 });

  // SRV parsing
  const srv = (data) => ({ type: 33, data });
  ok("srv: keeps targets under the domain, normalised and deduplicated",
    JSON.stringify(srvTargetsUnder("example.com", [
      srv("0 0 443 Mail.Example.com."), srv("10 5 443 mail.example.com"), srv("0 0 5061 sip.eu.example.com."),
    ])) === JSON.stringify(["mail.example.com", "sip.eu.example.com"]));
  ok("srv: third-party targets, the root itself, look-alikes and non-SRV answers are dropped",
    srvTargetsUnder("example.com", [
      srv("100 1 443 sipdir.online.lync.com."), srv("0 0 443 example.com."), srv("0 0 443 badexample.com."),
      { type: 5, data: "x.example.com." }, srv("garbage"), { type: 33, data: 7 },
    ]).length === 0);

  // SRV pass through the real module
  const queried = [];
  globalThis.fetch = async (value) => {
    const url = new URL(String(value));
    const name = url.searchParams.get("name"), type = url.searchParams.get("type");
    queried.push(`${type} ${name}`);
    if (type === "SRV" && name === "_autodiscover._tcp.example.com") return doh([srv("0 0 443 autodiscover.example.com.")]);
    if (type === "SRV" && name === "_sip._tls.example.com") return doh([srv("100 1 443 sipdir.online.lync.com.")]);
    return doh([]);
  };
  const brute = await runBruteforceModule("example.com", { cache: new Map() });
  globalThis.fetch = realFetch;
  ok("srv: every SRV label is queried once",
    SRV_DISCOVERY_LABELS.every((label) => queried.filter((q) => q === `SRV ${label}.example.com`).length === 1));
  ok("srv: an in-domain target becomes a discovered name with its record",
    JSON.stringify(brute.srv_items) === JSON.stringify([{ hostname: "autodiscover.example.com", source: "dns_srv", record: "_autodiscover._tcp.example.com" }]));
  ok("srv: answered counts records, not queries (2 of 8)", brute.srv_answered === 2 && brute.srv_checked === SRV_DISCOVERY_LABELS.length);
  ok("srv: names stay out of brute-force items, whose sources consumers classify",
    brute.items.every((item) => item.source !== "dns_srv") && brute.error === null);
  ok("srv: lookups are counted in the module's checked total",
    brute.checked === BRUTEFORCE_MAX_NAMES + 8 + SRV_DISCOVERY_LABELS.length);

  globalThis.fetch = async (value) => {
    const url = new URL(String(value));
    if (url.searchParams.get("type") === "SRV") throw new Error("resolver down");
    return doh(url.searchParams.get("name") === "www.example.com" ? [{ type: 1, data: "203.0.113.5" }] : []);
  };
  const srvDown = await runBruteforceModule("example.com", { cache: new Map() });
  globalThis.fetch = realFetch;
  ok("srv: a failing SRV lookup never fails the module or its A results",
    srvDown.error === null && srvDown.items.some((item) => item.hostname === "www.example.com") && srvDown.srv_items.length === 0);

  // Link extraction
  const html = `
    <a href="https://Portal.Example.com/login">x</a> <a href='//status.example.com'>s</a>
    <img src="https://cdn.eu.example.com/a.png"> <form action="https://forms.example.com/f"></form>
    <a href="/relative">r</a> <a href="https://example.com/">root</a> <a href="mailto:hi@example.com">m</a>
    <a href="javascript:void(0)">j</a> <a href="https://badexample.com/">l</a> <a href="https://shop.vendor.net/">v</a>
    <a href="ftp://files.example.com/">f</a> <a href="https://portal.example.com/again">dup</a>`;
  ok("links: absolute, protocol-relative, src and form targets under the domain",
    JSON.stringify(linkedHostnamesUnder("example.com", html, "https://www.example.com/"))
      === JSON.stringify(["portal.example.com", "status.example.com", "cdn.eu.example.com", "forms.example.com"]));
  ok("links: a redirect to another domain contributes no names from relative links",
    linkedHostnamesUnder("example.com", '<a href="/x">', "https://example.co.uk/").length === 0);
  const manyLinks = Array.from({ length: 40 }, (_, i) => `<a href="https://h${i}.example.com/">`).join("");
  ok("links: bounded to maxHosts", linkedHostnamesUnder("example.com", manyLinks, "https://example.com/").length === LINKED_HOST_LIMITS.maxHosts);

  // Link window through the real module
  const streamOf = (parts, { close = true } = {}) => new ReadableStream({
    start(controller) {
      for (const part of parts) controller.enqueue(new TextEncoder().encode(part));
      if (close) controller.close();
    },
  });
  const head = `<html><head><script src="/assets/index-abc.js"></script>${" ".repeat(5000)}</head><body>`;
  // The footer carries a CMS marker beyond the 4 KB snippet: technology
  // detection must not start reading it just because the link window did.
  const tail = `<footer><a href="https://careers.example.com/">Careers</a><link href="/wp-content/site.css"></footer></body></html>`;
  const htmlResponse = (body, type = "text/html; charset=utf-8") => async (value) => {
    const url = new URL(String(value));
    if (["cloudflare-dns.com", "dns.google"].includes(url.hostname)) return doh(url.searchParams.get("type") === "A" ? [{ type: 1, data: "93.184.216.34" }] : []);
    return new Response(body(), { status: 200, headers: { "content-type": type, server: "nginx" } });
  };

  globalThis.fetch = htmlResponse(() => streamOf([head, tail]));
  const without = await runTechModule("example.com", {});
  globalThis.fetch = htmlResponse(() => streamOf([head, tail]));
  const withWindow = await runTechModule("example.com", { remainingMs: () => 40_000 });
  globalThis.fetch = realFetch;
  ok("links: absent without runner time — not examined is never 'links to nothing'",
    !("linked_hostnames" in without) && !("linked_hostnames_bytes_read" in without));
  ok("links: a host linked beyond the 4 KB snippet is found when the window is admitted",
    JSON.stringify(withWindow.linked_hostnames) === JSON.stringify(["careers.example.com"]));
  ok("links: technology detection is byte-identical with and without the window",
    !without.technologies.includes("WordPress") && without.technologies.includes("React/Vite")
      && JSON.stringify(without.technologies) === JSON.stringify(withWindow.technologies)
      && JSON.stringify(without.technology_fingerprints) === JSON.stringify(withWindow.technology_fingerprints)
      && JSON.stringify(without.external_scripts) === JSON.stringify(withWindow.external_scripts));

  globalThis.fetch = htmlResponse(() => streamOf([head, tail]));
  const tight = await runTechModule("example.com", { remainingMs: () => LINKED_HOST_LIMITS.readMs + LINKED_HOST_LIMITS.marginMs - 1 });
  globalThis.fetch = htmlResponse(() => streamOf([head, tail]), "application/json");
  const notHtml = await runTechModule("example.com", { remainingMs: () => 40_000 });
  globalThis.fetch = realFetch;
  ok("links: not read when remaining time cannot cover window plus margin", !("linked_hostnames" in tight));
  ok("links: not read for a non-HTML response", !("linked_hostnames" in notHtml));

  globalThis.fetch = htmlResponse(() => streamOf([head, '<a href="https://early.example.com/">'], { close: false }));
  const stallStart = Date.now();
  const stalled = await runTechModule("example.com", { remainingMs: () => 40_000 });
  const stallMs = Date.now() - stallStart;
  globalThis.fetch = realFetch;
  ok("links: a body that never ends is cut at the read window",
    stallMs >= LINKED_HOST_LIMITS.readMs - 50 && stallMs < LINKED_HOST_LIMITS.readMs + 1_000);
  ok("links: what arrived before the cut is still used",
    JSON.stringify(stalled.linked_hostnames) === JSON.stringify(["early.example.com"]) && stalled.technologies.includes("nginx"));

  const big = "x".repeat(LINKED_HOST_LIMITS.maxBytes);
  globalThis.fetch = htmlResponse(() => streamOf([head, big, '<a href="https://beyond.example.com/">']));
  const capped = await runTechModule("example.com", { remainingMs: () => 40_000 });
  globalThis.fetch = realFetch;
  ok("links: never reads past maxBytes",
    capped.linked_hostnames_bytes_read === LINKED_HOST_LIMITS.maxBytes && !capped.linked_hostnames.includes("beyond.example.com"));

  let pulls = 0;
  const chunk16k = new TextEncoder().encode("y".repeat(16_384));
  globalThis.fetch = htmlResponse(() => new ReadableStream({
    pull(controller) { pulls += 1; controller.enqueue(chunk16k); },
  }, { highWaterMark: 0 }));
  await runTechModule("example.com", { remainingMs: () => 40_000 });
  globalThis.fetch = realFetch;
  ok("links: stops pulling an endless body once maxBytes have arrived",
    pulls > 0 && pulls <= Math.ceil(LINKED_HOST_LIMITS.maxBytes / chunk16k.byteLength) + 2);

  // Merge into discovery
  ok("merge: SRV then linked names follow CT/brute-force names, without duplicates",
    JSON.stringify(withReferencedHostnames(["a.example.com", "b.example.com"], {
      srvItems: [{ hostname: "c.example.com" }, { hostname: "a.example.com" }, null, { hostname: 5 }],
      linkedHostnames: ["d.example.com", "c.example.com", ""],
    })) === JSON.stringify(["a.example.com", "b.example.com", "c.example.com", "d.example.com"]));
  ok("merge: absent references leave discovery unchanged",
    JSON.stringify(withReferencedHostnames(["a.example.com"], { srvItems: undefined, linkedHostnames: undefined })) === JSON.stringify(["a.example.com"]));

  const engineSrc = fs.readFileSync(path.join(root, "workers/scan-api/src/engines/scan-engine.js"), "utf8");
  ok("wiring: production discovery appends SRV targets and home-page links",
    /const mergedSubdomainItems = withReferencedHostnames\(\[\.\.\.subdomainsResult\.items, \.\.\.bruteNewItems\], \{\s*srvItems: bruteforceResult\.srv_items,\s*linkedHostnames: techResult\?\.linked_hostnames,\s*\}\);/.test(engineSrc));
  ok("wiring: only durable runs give the technology module remaining time",
    /runTechModule\(domain, \{ dnsResolver: dnsQuery, dnsCache, accounting, signal, remainingMs: durableInvocation \? remainingMs : null \}\)/.test(engineSrc));
}

console.log(`\nexposure-honesty: ${pass} passed, ${fail} failed`);
if (fail > 0) process.exit(1);
