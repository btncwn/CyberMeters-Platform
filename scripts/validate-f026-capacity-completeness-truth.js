#!/usr/bin/env node
//
// F-026 — capacity/completeness truth. Two defects, closed together:
//   (a) subdomain_takeover silently truncates at 100 hosts: a 101-host scan
//       reports checked:100 with NO signal that a host was dropped, so the
//       customer believes full coverage. Truncation must be EXPLICIT and the
//       partial-truth must propagate up (unmeasured/partial is never "healthy").
//   (b) buildScanQuality keeps three different facts separate: the authenticated
//       Workers Paid provider ceiling is 10,000; the configured legacy
//       admission/report effective_limit is 200; and legacy mode does not install
//       the reserved path's physical whole-scan counter.
//   (c) source-bounded variable outbound paths remain below the Paid provider
//       ceiling without pretending that 200 is a physical per-scan hard cap.
//
// Red-first through the real producers (runTakeoverScan, buildScanQuality). Node 24+.

import { runTakeoverModule } from "../workers/scan-api/src/engines/takeover-scan.js";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { buildScanQuality, computeScanBudget } from "../workers/scan-api/src/engines/scan-engine.js";
import { resolveScanCapacity } from "../workers/scan-api/src/engines/scan-budget.js";
import { BRUTEFORCE_MAX_NAMES } from "../workers/scan-api/src/engines/subdomains-scan.js";
import { RESERVED_MAX_REDIRECT_HOPS } from "../workers/scan-api/src/engines/reserved-probe.js";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const source = (rel) => fs.readFileSync(path.join(root, rel), "utf8");
const integerLiteral = (text, pattern, label) => {
  const match = text.match(pattern);
  if (!match) throw new Error(`missing source-bound integer: ${label}`);
  return Number.parseInt(match[1].replaceAll("_", ""), 10);
};

let pass = 0, fail = 0;
const ok = (name, cond, detail = "") => { cond ? pass++ : fail++; console.log(`${cond ? "PASS" : "FAIL"} ${name}${cond ? "" : (detail ? " — " + detail : "")}`); };

// ── (a) takeover truncation truth ────────────────────────────────────────────
// A CNAME resolver that answers NODATA for every host: no candidates, no fetches,
// so the run is deterministic and offline. We only assert coverage bookkeeping.
const noCnameDns = async () => ({ Answer: [] });

async function takeoverTruncation() {
  const hosts101 = Array.from({ length: 101 }, (_, i) => `h${i}.example.com`);
  const res = await runTakeoverModule("example.com", hosts101, { dnsQueryImpl: noCnameDns });

  ok("(a) 101 hosts: exactly 100 were actually checked",
    res.checked === 100, `checked=${res.checked}`);
  ok("(a) truncation is EXPLICIT — totals name the requested vs checked counts",
    res.totals && res.totals.requested === 101 && res.totals.checked === 100 && res.totals.omitted === 1,
    JSON.stringify(res.totals));
  ok("(a) a truncated run is flagged incomplete, never silently full",
    res.incomplete === true, `incomplete=${res.incomplete}`);
  ok("(a) the incomplete carries a machine reason naming the host cap",
    /truncat|host_cap|cap/i.test(String(res.incomplete_reason || "")), String(res.incomplete_reason));

  const hosts50 = Array.from({ length: 50 }, (_, i) => `h${i}.example.com`);
  const within = await runTakeoverModule("example.com", hosts50, { dnsQueryImpl: noCnameDns });
  ok("(a) control: a within-cap run is NOT flagged incomplete",
    within.incomplete === false && within.totals.omitted === 0,
    JSON.stringify({ incomplete: within.incomplete, totals: within.totals }));
}

// ── (a-propagation) scan_quality must inherit the takeover partial-truth ──────
function completeMod() {
  return { dns: {}, ssl: {}, headers: {}, email_security: {}, dmarc_core: {} };
}
function scanQualityWithTruncatedTakeover() {
  const modules = {
    ...completeMod(),
    subdomain_takeover: { checked: 100, incomplete: true, incomplete_reason: "host_cap_truncation",
      totals: { requested: 101, checked: 100, omitted: 1 }, risks: [], potential_risks: 0 },
  };
  const q = buildScanQuality(modules);
  ok("(a-prop) a truncated takeover degrades scan_quality to partial",
    q.status === "partial", `status=${q.status}`);
  ok("(a-prop) the takeover is listed as incomplete, not silently dropped",
    (q.modules_incomplete || []).includes("subdomain_takeover") ||
    (q.modules_skipped || []).includes("subdomain_takeover"),
    JSON.stringify({ inc: q.modules_incomplete, skip: q.modules_skipped }));

  // (a-prop F1): a LOOKUP-FAILURE incomplete flows through the SAME generic
  // buildScanQuality channel — a takeover that measured nothing is never healthy.
  const failModules = {
    ...completeMod(),
    subdomain_takeover: { checked: 50, incomplete: true, incomplete_reason: "host_lookup_failure",
      incomplete_reasons: ["host_lookup_failure"],
      totals: { requested: 50, checked: 50, omitted: 0, lookup_failed: 50 }, risks: [], potential_risks: 0 },
  };
  const qf = buildScanQuality(failModules);
  ok("(a-prop F1) a lookup-failure takeover also degrades scan_quality to partial",
    qf.status === "partial" &&
      ((qf.modules_incomplete || []).includes("subdomain_takeover") ||
       (qf.modules_skipped || []).includes("subdomain_takeover")),
    JSON.stringify({ status: qf.status, inc: qf.modules_incomplete }));

  // (a-prop CONTRACT-EXT): an UNCONFIRMED-probe incomplete also flows the same
  // generic buildScanQuality channel — a candidate whose probe was refused is
  // never rendered healthy by API/snapshot consumers of scan_quality.
  const uncModules = {
    ...completeMod(),
    subdomain_takeover: { checked: 5, incomplete: true, incomplete_reason: "host_probe_unconfirmed",
      incomplete_reasons: ["host_probe_unconfirmed"],
      totals: { requested: 5, checked: 5, omitted: 0, lookup_failed: 0, unconfirmed: 5 }, risks: [], potential_risks: 5 },
  };
  const qu = buildScanQuality(uncModules);
  ok("(a-prop CE) an unconfirmed-probe takeover also degrades scan_quality to partial",
    qu.status === "partial" &&
      ((qu.modules_incomplete || []).includes("subdomain_takeover") ||
       (qu.modules_skipped || []).includes("subdomain_takeover")),
    JSON.stringify({ status: qu.status, inc: qu.modules_incomplete }));
}

// ── (b) capacity truth: provider, admission/report and physical are distinct ──
function capacityTruth() {
  const wrangler = source("workers/scan-api/wrangler.toml");
  const configuredMode = wrangler.match(/^SCAN_CAPACITY_MODE\s*=\s*"([^"]+)"/m)?.[1];
  const configuredLimit = integerLiteral(
    wrangler,
    /^SCAN_SUBREQUEST_LIMIT\s*=\s*([\d_]+)/m,
    "SCAN_SUBREQUEST_LIMIT",
  );
  const capacity = resolveScanCapacity({
    SCAN_CAPACITY_MODE: configuredMode,
    SCAN_SUBREQUEST_LIMIT: configuredLimit,
  });
  const round3Estimate = computeScanBudget(23);
  const q = buildScanQuality({ ...completeMod(), scan_budget: round3Estimate }, undefined, capacity);
  const b = q.subrequest_budget || {};
  const engineSource = source("workers/scan-api/src/engines/scan-engine.js");
  const reservedBranchStart = engineSource.indexOf("if (reservedMode) {");
  const legacyBranchStart = engineSource.indexOf("} else {", reservedBranchStart);
  const physicalAssignment = engineSource.indexOf("reservedPhysicalCounter = reserved.physicalCounter;");

  ok("(b) candidate resolves explicit legacy admission/report effective_limit 200",
    capacity.mode === "legacy" && capacity.limit === 200 && b.effective_limit === 200,
    JSON.stringify({ capacity, budget: b }));
  ok("(b) provider ceiling is reported as 10000, never substituted for effective_limit",
    b.platform_ceiling === 10_000 && b.effective_limit !== b.platform_ceiling,
    JSON.stringify(b));
  ok("(b) remaining estimate is computed against the EFFECTIVE limit",
    b.remaining_estimate === 105 && b.remaining_estimate === Math.max(0, capacity.limit - (b.estimated ?? 0)),
    JSON.stringify(b));
  ok("(b) legacy 200 is not configured as a provider-enforced physical hard cap",
    !/^\s*subrequests\s*=/m.test(wrangler) &&
      engineSource.includes('const reservedMode = capacity.mode === "reserved";') &&
      reservedBranchStart >= 0 && legacyBranchStart > reservedBranchStart &&
      physicalAssignment > reservedBranchStart && physicalAssignment < legacyBranchStart,
    JSON.stringify({
      has_provider_subrequests_key: /^\s*subrequests\s*=/m.test(wrangler),
      reservedBranchStart,
      legacyBranchStart,
      physicalAssignment,
    }));

  // Guess-guard: another capacity must still flow through. This checks derivation,
  // not physical enforcement.
  const q2 = buildScanQuality(completeMod(), undefined, resolveScanCapacity({ SCAN_SUBREQUEST_LIMIT: 120 }));
  ok("(b) a different resolved capacity (120) flows through — not a guessed constant",
    q2.subrequest_budget.effective_limit === 120, JSON.stringify(q2.subrequest_budget));
}

// ── (c) source-bounded variable outbound envelope under provider 10,000 ─────
// This is deliberately NOT a physical whole-scan counter. It freezes the existing
// cardinality and redirect bounds for the host-driven external paths named by the
// Route-A decision. The valid CNAME path has one CNAME RRset member per DNS owner;
// cache reuse can only reduce the conservative arithmetic below.
function variableOutboundBoundTruth() {
  const subdomainsSource = source("workers/scan-api/src/engines/subdomains-scan.js");
  const attackLifecycleSource = source("workers/scan-api/src/engines/attack-surface-lifecycle.js");
  const assetSource = source("workers/scan-api/src/engines/asset-intel.js");
  const takeoverSource = source("workers/scan-api/src/engines/takeover-scan.js");
  const httpSource = source("workers/scan-api/src/lib/http.js");
  const ssrfSource = source("workers/scan-api/src/lib/ssrf.js");
  const engineSource = source("workers/scan-api/src/engines/scan-engine.js");

  const ctMergeCap = integerLiteral(subdomainsSource, /const MERGE_CAP\s*=\s*([\d_]+)/, "CT MERGE_CAP");
  const mailLabelsBlock = subdomainsSource.match(/const MAIL_SUBDOMAIN_LABELS\s*=\s*\[([\s\S]*?)\];/)?.[1] || "";
  const mailLabelCount = (mailLabelsBlock.match(/"[^"]+"/g) || []).length;
  const bruteHostCap = BRUTEFORCE_MAX_NAMES + mailLabelCount;
  const knownAssetCap = integerLiteral(attackLifecycleSource, /const MAX_RECHECK_HOSTS\s*=\s*([\d_]+)/, "MAX_RECHECK_HOSTS");
  const exposureHostCap = integerLiteral(assetSource, /const targets\s*=\s*candidates\.slice\(0,\s*([\d_]+)\)/, "exposure host cap");
  const takeoverHostCap = integerLiteral(takeoverSource, /const HOST_CAP\s*=\s*([\d_]+)/, "takeover HOST_CAP");
  const takeoverRedirectHops = integerLiteral(httpSource, /const MAX_REDIRECT_HOPS\s*=\s*([\d_]+)/, "takeover redirect hops");
  const protocolBlock = assetSource.match(/for \(const proto of \[([^\]]+)\]\)/)?.[1] || "";
  const protocolCount = (protocolBlock.match(/"[^"]+"/g) || []).length;

  const exposureHasTwoRemovalDnsQueries = /dnsQuery\(host, "A"[\s\S]*dnsQuery\(host, "AAAA"/.test(assetSource);
  const ssrfHasTwoAddressQueries = /Promise\.allSettled\(\[dnsQuery\(domain, "A"\), dnsQuery\(domain, "AAAA"\)\]\)/.test(ssrfSource);
  const exposureRedirectAttempts = RESERVED_MAX_REDIRECT_HOPS + 1;
  const exposurePerHostBound = 2 + protocolCount * exposureRedirectAttempts * (2 + 1);
  const exposureOutboundBound = exposureHostCap * exposurePerHostBound;
  const takeoverPerHostBound = 1 + takeoverRedirectHops + 1;
  const takeoverOutboundBound = takeoverHostCap * takeoverPerHostBound;
  const namedVariableOutboundBound = bruteHostCap + exposureOutboundBound + takeoverOutboundBound;
  const fixedModeledEstimate = computeScanBudget(bruteHostCap).estimated_subrequests_total - bruteHostCap;
  const conservativeProfileEnvelope = fixedModeledEstimate + namedVariableOutboundBound;
  const providerCeiling = buildScanQuality(completeMod(), undefined, resolveScanCapacity({ SCAN_SUBREQUEST_LIMIT: 200 }))
    .subrequest_budget.platform_ceiling;

  const adminStart = assetSource.indexOf("export function runAdminSurfaceModule");
  const adminEnd = assetSource.indexOf("\nexport function ", adminStart + 1);
  const adminBody = adminStart >= 0 ? assetSource.slice(adminStart, adminEnd >= 0 ? adminEnd : undefined) : "";
  const adminIsPure = adminBody.length > 0 && !/\b(fetch|dnsQuery|safeFetch|probeAsset)\s*\(/.test(adminBody) &&
    engineSource.includes("modules.admin_surface_detection = runAdminSurfaceModule(modules);");

  ok("(c) discovered and historical candidates are source-bounded before variable probes",
    ctMergeCap === 300 && bruteHostCap === 23 && knownAssetCap === 50 &&
      exposureHostCap === 50 && takeoverHostCap === 100,
    JSON.stringify({ ctMergeCap, bruteHostCap, knownAssetCap, exposureHostCap, takeoverHostCap }));
  ok("(c) exposure redirect/DNS fan-out is source-bounded",
    protocolCount === 2 && RESERVED_MAX_REDIRECT_HOPS === 3 &&
      exposureHasTwoRemovalDnsQueries && ssrfHasTwoAddressQueries &&
      exposurePerHostBound === 26 && exposureOutboundBound === 1300,
    JSON.stringify({ protocolCount, redirectHops: RESERVED_MAX_REDIRECT_HOPS, exposurePerHostBound, exposureOutboundBound }));
  ok("(c) takeover valid-CNAME path is source-bounded",
    takeoverRedirectHops === 4 && takeoverPerHostBound === 6 && takeoverOutboundBound === 600,
    JSON.stringify({ takeoverRedirectHops, takeoverPerHostBound, takeoverOutboundBound }));
  ok("(c) admin_surface is derived from completed exposure evidence with zero new network I/O",
    adminIsPure, JSON.stringify({ adminStart, adminEnd }));
  ok("(c) conservative named-variable envelope stays below provider 10000 but above admission 200",
    conservativeProfileEnvelope === 1995 &&
      conservativeProfileEnvelope > 200 && conservativeProfileEnvelope < providerCeiling,
    JSON.stringify({ fixedModeledEstimate, namedVariableOutboundBound, conservativeProfileEnvelope, providerCeiling }));
}

// ── (a2) lookup-failure completeness (F-026 R1 F1) — five cases ───────────────
// A failing CNAME resolver: every lookup rejects. An answering one: NODATA.
const failDns = async () => { throw new Error("dns_indeterminate"); };
async function lookupFailureCompleteness() {
  const mk = (n) => Array.from({ length: n }, (_, i) => `h${i}.example.com`);

  // (i) all-fail: 50 hosts, every lookup fails → incomplete, NOT healthy-complete.
  const allFail = await runTakeoverModule("example.com", mk(50), { dnsQueryImpl: failDns });
  ok("(a2-all-fail) total lookup failure is incomplete, never complete+healthy",
    allFail.incomplete === true && allFail.totals.lookup_failed === 50 && allFail.potential_risks === 0,
    JSON.stringify({ inc: allFail.incomplete, tot: allFail.totals }));
  ok("(a2-all-fail) reason names the lookup failure",
    /host_lookup_failure/.test(String(allFail.incomplete_reason)) &&
      (allFail.incomplete_reasons || []).includes("host_lookup_failure"),
    JSON.stringify(allFail.incomplete_reasons));

  // (ii) mixed-fail: within cap, some lookups fail → incomplete, counts exact.
  let call = 0;
  const halfDns = async () => { call++; if (call % 2 === 0) throw new Error("x"); return { Answer: [] }; };
  const mixed = await runTakeoverModule("example.com", mk(10), { dnsQueryImpl: halfDns });
  ok("(a2-mixed) partial lookup failure flags incomplete with an exact count",
    mixed.incomplete === true && mixed.totals.lookup_failed === 5 && mixed.totals.omitted === 0,
    JSON.stringify(mixed.totals));

  // (iii) cap-only: 101 hosts, all lookups succeed → truncation reason ONLY.
  const capOnly = await runTakeoverModule("example.com", mk(101), { dnsQueryImpl: noCnameDns });
  ok("(a2-cap-only) truncation without failure carries only the truncation reason",
    capOnly.incomplete === true && capOnly.incomplete_reasons.length === 1 &&
      capOnly.incomplete_reasons[0] === "host_cap_truncation" && capOnly.totals.lookup_failed === 0,
    JSON.stringify(capOnly.incomplete_reasons));

  // (iv) cap+fail: 101 hosts AND every lookup fails → BOTH reasons coexist.
  const capFail = await runTakeoverModule("example.com", mk(101), { dnsQueryImpl: failDns });
  ok("(a2-cap+fail) truncation AND lookup failure both appear, neither overwrites",
    capFail.incomplete === true &&
      capFail.incomplete_reasons.includes("host_cap_truncation") &&
      capFail.incomplete_reasons.includes("host_lookup_failure") &&
      capFail.totals.omitted === 1 && capFail.totals.lookup_failed === 100,
    JSON.stringify({ r: capFail.incomplete_reasons, t: capFail.totals }));

  // (v) zero-fail within cap: all lookups succeed → COMPLETE (no over-correction).
  const clean = await runTakeoverModule("example.com", mk(30), { dnsQueryImpl: noCnameDns });
  ok("(a2-zero-fail) a fully-measured within-cap run stays COMPLETE",
    clean.incomplete === false && clean.incomplete_reasons.length === 0 &&
      clean.totals.lookup_failed === 0 && clean.totals.omitted === 0,
    JSON.stringify({ inc: clean.incomplete, t: clean.totals }));
}

// ── (a3) unconfirmed-probe completeness (F-026 R1 CONTRACT EXTENSION) ─────────
// A CNAME that targets a takeover-prone provider makes the host a CANDIDATE; the
// body probe then confirms/denies. A refused (SSRF null) or failed (reject) or
// unreadable probe leaves the host UNMEASURED — the same false-healthy class as
// a lookup failure, one stage later. These must flag incomplete too.
const vulnCname = async () => ({ Answer: [{ data: "victim.github.io" }] });
const fetchReject = async () => { throw new Error("network"); };          // fetch_failed
const fetchRefused = async () => null;                                     // probe_refused (SSRF guard)
const fetchClaimed = async () => ({ ok: true, status: 200,                 // conclusively claimed (NOT unconfirmed)
  text: async () => "a normal live page, no takeover marker" });
async function unconfirmedCompleteness() {
  const mk = (n) => Array.from({ length: n }, (_, i) => `h${i}.example.com`);

  const failP = await runTakeoverModule("example.com", mk(5),
    { dnsQueryImpl: vulnCname, fetcher: fetchReject });
  ok("(a3-fetch-failed) a failed probe leaves the host unmeasured -> incomplete",
    failP.incomplete === true && failP.totals.unconfirmed === 5 &&
      failP.incomplete_reasons.includes("host_probe_unconfirmed"),
    JSON.stringify({ inc: failP.incomplete, t: failP.totals, r: failP.incomplete_reasons }));

  const refP = await runTakeoverModule("example.com", mk(5),
    { dnsQueryImpl: vulnCname, fetcher: fetchRefused });
  ok("(a3-probe-refused) a refused probe (SSRF null) -> incomplete, not healthy",
    refP.incomplete === true && refP.totals.unconfirmed === 5 &&
      refP.incomplete_reasons.includes("host_probe_unconfirmed") && refP.potential_risks === 5,
    JSON.stringify({ inc: refP.incomplete, t: refP.totals }));

  // cap + unconfirmed: 101 vuln candidates, all probes refused -> BOTH reasons.
  const capUnc = await runTakeoverModule("example.com", mk(101),
    { dnsQueryImpl: vulnCname, fetcher: fetchRefused });
  ok("(a3-cap+unconfirmed) truncation AND probe-unconfirmed coexist, no overwrite",
    capUnc.incomplete_reasons.includes("host_cap_truncation") &&
      capUnc.incomplete_reasons.includes("host_probe_unconfirmed") &&
      capUnc.totals.omitted === 1 && capUnc.totals.unconfirmed === 100,
    JSON.stringify({ r: capUnc.incomplete_reasons, t: capUnc.totals }));

  // mixed doors: lookup failure AND unconfirmed in one run (disjoint hosts).
  let n = 0;
  const halfVuln = async () => { n++; if (n % 2 === 0) throw new Error("dns"); return { Answer: [{ data: "victim.github.io" }] }; };
  const mixed = await runTakeoverModule("example.com", mk(10),
    { dnsQueryImpl: halfVuln, fetcher: fetchRefused });
  ok("(a3-mixed-doors) lookup-failure and probe-unconfirmed both counted, no double count",
    mixed.totals.lookup_failed === 5 && mixed.totals.unconfirmed === 5 &&
      mixed.totals.lookup_failed + mixed.totals.unconfirmed === 10 &&
      mixed.incomplete_reasons.includes("host_lookup_failure") &&
      mixed.incomplete_reasons.includes("host_probe_unconfirmed"),
    JSON.stringify(mixed.totals));

  // all-success: candidates confirmed claimed (no marker) -> COMPLETE, no over-correction.
  const clean = await runTakeoverModule("example.com", mk(5),
    { dnsQueryImpl: vulnCname, fetcher: fetchClaimed });
  ok("(a3-all-success) confirmed-claimed candidates leave the run COMPLETE",
    clean.incomplete === false && clean.totals.unconfirmed === 0 &&
      clean.incomplete_reasons.length === 0,
    JSON.stringify({ inc: clean.incomplete, t: clean.totals }));
}

// ── (a4) unconfirmed denominator is PER-HOST, never per-candidate (R1 #2) ──────
// A host may carry MORE THAN ONE vulnerable CNAME answer — a two-hop chain
// (alias -> terminal, both on a takeover-prone provider) or duplicate answers.
// Each answer becomes its own unconfirmed[] candidate row, but they are ONE
// unmeasured host. totals.unconfirmed must collapse to distinct hosts, or the
// denominator double-counts and lookup_failed + unconfirmed <= checked breaks.
// The candidate rows themselves are preserved verbatim as forensic detail.
const twoHopVulnCname = async () => ({
  Answer: [{ data: "alias.github.io" }, { data: "terminal.github.io" }],
});
const duplicateVulnCname = async () => ({
  Answer: [{ data: "victim.github.io" }, { data: "victim.github.io" }],
});
// Invariant that must hold on EVERY module result: the disjoint per-reason host
// totals can never exceed the number of hosts actually checked.
function assertCoverageInvariant(label, res) {
  const t = res.totals || {};
  ok(`(a4-inv) ${label}: lookup_failed + unconfirmed <= checked`,
    (t.lookup_failed || 0) + (t.unconfirmed || 0) <= (t.checked || 0),
    JSON.stringify(t));
}
async function unconfirmedPerHostDenominator() {
  const one = ["h.example.com"];

  // Two-hop chain, both answers refused -> ONE host, TWO candidate rows.
  const twoHop = await runTakeoverModule("example.com", one,
    { dnsQueryImpl: twoHopVulnCname, fetcher: fetchRefused });
  ok("(a4-two-hop) totals.unconfirmed counts the DISTINCT host (1), not candidates (2)",
    twoHop.totals.unconfirmed === 1 && twoHop.totals.checked === 1,
    JSON.stringify(twoHop.totals));
  ok("(a4-two-hop) candidate-level forensic detail is PRESERVED (2 unconfirmed rows)",
    Array.isArray(twoHop.unconfirmed) && twoHop.unconfirmed.length === 2 &&
      Array.isArray(twoHop.unconfirmed_hosts) && twoHop.unconfirmed_hosts.length === 1 &&
      twoHop.unconfirmed_hosts[0] === "h.example.com",
    JSON.stringify({ rows: twoHop.unconfirmed.length, hosts: twoHop.unconfirmed_hosts }));
  ok("(a4-two-hop) still incomplete with the probe-unconfirmed reason",
    twoHop.incomplete === true && twoHop.incomplete_reasons.includes("host_probe_unconfirmed"),
    JSON.stringify(twoHop.incomplete_reasons));
  assertCoverageInvariant("two-hop", twoHop);

  // Duplicate identical answers, refused -> ONE host, TWO candidate rows.
  const dup = await runTakeoverModule("example.com", one,
    { dnsQueryImpl: duplicateVulnCname, fetcher: fetchRefused });
  ok("(a4-duplicate) identical answers collapse to ONE unmeasured host",
    dup.totals.unconfirmed === 1 && dup.unconfirmed.length === 2 &&
      dup.unconfirmed_hosts.length === 1,
    JSON.stringify({ t: dup.totals, rows: dup.unconfirmed.length }));
  assertCoverageInvariant("duplicate", dup);

  // The invariant also holds on the multi-candidate mixed-door and cap cases.
  const mk = (n) => Array.from({ length: n }, (_, i) => `h${i}.example.com`);
  let n = 0;
  const halfVuln = async () => { n++; if (n % 2 === 0) throw new Error("dns"); return { Answer: [{ data: "victim.github.io" }] }; };
  assertCoverageInvariant("mixed-doors",
    await runTakeoverModule("example.com", mk(10), { dnsQueryImpl: halfVuln, fetcher: fetchRefused }));
  assertCoverageInvariant("cap+unconfirmed",
    await runTakeoverModule("example.com", mk(101), { dnsQueryImpl: vulnCname, fetcher: fetchRefused }));

  // Over-correction control: DISTINCT vulnerable hosts each still count once.
  const many = await runTakeoverModule("example.com", mk(3),
    { dnsQueryImpl: vulnCname, fetcher: fetchRefused });
  ok("(a4-distinct-hosts) three distinct unmeasured hosts count as three",
    many.totals.unconfirmed === 3 && many.unconfirmed_hosts.length === 3,
    JSON.stringify(many.totals));
  assertCoverageInvariant("three-distinct", many);
}

// ── (a5) canonical host identity at the PRODUCER boundary (delta R1 #2) ────────
// Case, surrounding whitespace, and one-OR-MORE trailing dots collapse to ONE DNS
// host BEFORE the cap and before every door, so requested/checked/lookup_failed/
// unconfirmed share one per-host basis: a spelling variant can neither inflate the
// denominator, split one host across two doors, nor occupy a second cap slot. The
// earlier fix collapsed only the final unconfirmed_hosts list; this closes the
// producer boundary so checked and lookup_failed are canonical too.
async function canonicalHostBoundary() {
  // (i) case + single trailing-dot equivalence: two spellings of ONE host, refused.
  const caseDot = await runTakeoverModule("example.com", ["Sub.Example.COM", "sub.example.com."],
    { dnsQueryImpl: vulnCname, fetcher: fetchRefused });
  ok("(a5-case-dot) case+trailing-dot spellings collapse to ONE canonical host",
    caseDot.totals.requested === 1 && caseDot.totals.checked === 1 &&
      caseDot.totals.unconfirmed === 1 && caseDot.unconfirmed_hosts.length === 1 &&
      caseDot.unconfirmed_hosts[0] === "sub.example.com",
    JSON.stringify({ t: caseDot.totals, h: caseDot.unconfirmed_hosts }));
  ok("(a5-case-dot) dedupe happens BEFORE probing — one canonical host, one forensic probe",
    caseDot.unconfirmed.length === 1, JSON.stringify(caseDot.unconfirmed));
  assertCoverageInvariant("case-dot", caseDot);

  // (ii) MULTIPLE trailing dots collapse consistently too.
  const multiDot = await runTakeoverModule("example.com", ["m.example.com..", "m.example.com"],
    { dnsQueryImpl: vulnCname, fetcher: fetchRefused });
  ok("(a5-multi-dot) one OR MORE trailing dots collapse to one canonical host",
    multiDot.totals.checked === 1 && multiDot.unconfirmed_hosts.length === 1 &&
      multiDot.unconfirmed_hosts[0] === "m.example.com",
    JSON.stringify({ t: multiDot.totals, h: multiDot.unconfirmed_hosts }));
  assertCoverageInvariant("multi-dot", multiDot);

  // (iii) duplicate input before cap: a spelling variant must not EVICT a distinct
  // host from the 100-cap. 100 copies of one host + one more distinct host -> raw
  // slice(0,100) would drop the distinct host and report checked:100; canonical
  // dedupe keeps BOTH and reports the honest count.
  const dupInputs = Array.from({ length: 100 }, () => "x.example.com").concat(["y.example.com"]);
  const capDup = await runTakeoverModule("example.com", dupInputs, { dnsQueryImpl: noCnameDns });
  ok("(a5-cap-dedupe) duplicates do not consume cap slots — the distinct host is still checked",
    capDup.totals.requested === 2 && capDup.totals.checked === 2 && capDup.totals.omitted === 0 &&
      capDup.checked_hosts.includes("y.example.com"),
    JSON.stringify({ t: capDup.totals, checked: capDup.checked_hosts.length }));
  assertCoverageInvariant("cap-dedupe", capDup);

  // (iv) mixed-door canonical equivalence: two spellings of ONE host whose lookup
  // FAILS land as ONE host in ONE door (lookup_failed), never split across doors.
  const mixedCanon = await runTakeoverModule("example.com", ["Z.example.com", "z.example.com."],
    { dnsQueryImpl: failDns });
  ok("(a5-mixed-door) canonical-equal spellings land as ONE host in ONE door",
    mixedCanon.totals.requested === 1 && mixedCanon.totals.checked === 1 &&
      mixedCanon.totals.lookup_failed === 1 && mixedCanon.totals.unconfirmed === 0 &&
      mixedCanon.lookup_failed_hosts.length === 1,
    JSON.stringify({ t: mixedCanon.totals, lf: mixedCanon.lookup_failed_hosts }));
  assertCoverageInvariant("mixed-door-canonical", mixedCanon);

  // (v) over-correction guard: genuinely DISTINCT hosts are NOT collapsed.
  const distinct = await runTakeoverModule("example.com",
    ["a.example.com", "b.example.com", "c.example.com"], { dnsQueryImpl: failDns });
  ok("(a5-distinct) genuinely distinct hosts are preserved, never over-collapsed",
    distinct.totals.requested === 3 && distinct.totals.checked === 3 && distinct.totals.lookup_failed === 3,
    JSON.stringify(distinct.totals));
  assertCoverageInvariant("distinct-preserved", distinct);
}

await lookupFailureCompleteness();
await unconfirmedCompleteness();
await unconfirmedPerHostDenominator();
await canonicalHostBoundary();
await takeoverTruncation();
scanQualityWithTruncatedTakeover();
capacityTruth();
variableOutboundBoundTruth();

console.log(`\nF-026 capacity/completeness truth: ${pass} passed, ${fail} failed`);
if (fail) process.exit(1);
