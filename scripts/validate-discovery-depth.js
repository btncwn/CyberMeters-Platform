#!/usr/bin/env node
//
// Discovery depth: a rotating slice of the authored word list, name variants
// of found hosts and a bounded DNSSEC NSEC walk, each confirmed by DNS.
//
// Proves, against the real module and the real scan engine:
//   • successive completed scans check successive slices, so the whole list is
//     covered over time, and no scan checks more than its bounds;
//   • guesses whose answer is exactly the zone's wildcard answer are not
//     admitted; names the zone itself lists are admitted and flagged instead;
//   • names already known are never asked about again, and every name that
//     could not be confirmed or was not asked is counted;
//   • every guess asks A, and AAAA unless A proved the name does not exist, so
//     an IPv6-only name is found; a dangling alias is kept as the name it is;
//   • every question spends the shared discovery budget, and names left
//     unasked by it are stated; variants below a sub-zone that answers every
//     name are not admitted;
//   • the soft time budget stops new lookups and says so;
//   • a durable scan admits confirmed names into discovery, takeover checks and
//     the inventory with their source; the waitUntil path runs nothing; a scan
//     whose wildcard check did not finish runs no guesses.
// In-memory mutants of the module must each be rejected by the fixtures.
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const enginePath = (file) => path.join(root, "workers", "scan-api", "src", "engines", file);
const eng = (file) => import(pathToFileURL(enginePath(file)).href);
const modulePath = enginePath("discovery-depth.js");
const moduleSource = fs.readFileSync(modulePath, "utf8");

let pass = 0, fail = 0;
const ok = (name, condition, detail = "") => {
  if (condition) pass++;
  else { fail++; console.log(`FAIL ${name}${detail ? ` — ${detail}` : ""}`); }
};

const answer = (name, ip) => ({ Status: 0, Answer: [{ name, type: 1, TTL: 60, data: ip }] });
const answer6 = (name, ip) => ({ Status: 0, Answer: [{ name, type: 28, TTL: 60, data: ip }] });
const nxdomain = { Status: 3, Answer: [] };
const nsecRecord = (owner, next, types = "A RRSIG NSEC") => ({ name: `${owner}.`, type: 47, TTL: 300, data: `${next}. ${types}` });
// A signed zone whose NSEC chain lists `labels` (one-label names, canonical
// order), closing back at the apex.
function signedZoneOf(labels) {
  const owners = ["example.com", ...[...labels].sort().map((label) => `${label}.example.com`)];
  const zone = new Map();
  owners.forEach((owner, index) => {
    const next = owners[(index + 1) % owners.length];
    zone.set(owner, nsecRecord(owner, next, owner === "example.com" ? "A NS SOA MX RRSIG NSEC DNSKEY" : "A RRSIG NSEC"));
  });
  return zone;
}
const nsecLookupFor = (zone) => async (name) => (zone.has(name)
  ? { Status: 0, AD: true, Answer: [zone.get(name)] }
  : { Status: 0, Answer: [] });
const signedZone = signedZoneOf(["hidden", "mail"]);
const unsignedNsecLookup = async () => ({ Status: 0, Answer: [] });

async function fixtures(api) {
  let checks = 0;
  const { DISCOVERY_DEPTH_LIMITS: limits, wordlistRotation } = api;
  const { DISCOVERY_WORDLIST } = await eng("discovery-wordlist.js");

  // Rotation: successive scans, successive slices; the list wraps.
  const first = wordlistRotation(0), second = wordlistRotation(1);
  assert.equal(first.cursor, 0, "rotation: the first scan starts at the top"); checks++;
  assert.equal(first.labels.length, limits.wordlistSlice, "rotation: a slice is the configured size"); checks++;
  assert.equal(second.cursor, limits.wordlistSlice, "rotation: the next completed scan checks the next slice"); checks++;
  assert.ok(!second.labels.some((label) => first.labels.includes(label)), "rotation: consecutive slices do not overlap"); checks++;
  const covered = new Set();
  for (let index = 0; index < Math.ceil(DISCOVERY_WORDLIST.length / limits.wordlistSlice); index++) {
    for (const label of wordlistRotation(index).labels) covered.add(label);
  }
  assert.equal(covered.size, DISCOVERY_WORDLIST.length, "rotation: one pass of scans covers the whole list"); checks++;
  assert.equal(wordlistRotation(-3).cursor, 0, "rotation: an invalid index starts at the top"); checks++;

  // A run against an unsigned zone with a wildcard answer.
  const asked = [];
  const firstSlice = first.labels.map((label) => `${label}.example.com`);
  const responses = new Map([
    [firstSlice[0], answer(firstSlice[0], "203.0.113.1")],
    [firstSlice[1], answer(firstSlice[1], "198.51.100.9")],
    [firstSlice[2], { Status: 0, Answer: [{ name: firstSlice[2], type: 5, TTL: 60, data: "edge.provider.test." }] }],
    [firstSlice[3], { Status: 0, Answer: [] }],
    [firstSlice[4], { Status: 2, Answer: [] }],
    ["shop02.example.com", answer("shop02.example.com", "203.0.113.2")],
  ]);
  const lookup = async (name, type) => {
    asked.push(`${type} ${name}`);
    if (name === firstSlice[5]) throw new Error("network down");
    return responses.get(name) ?? nxdomain;
  };
  const known = [firstSlice[6], "api.example.com", "shop01.example.com"];
  const result = await api.runDiscoveryDepth("example.com", {
    knownHosts: known, discoveredHosts: ["api.example.com", "shop01.example.com"], wildcardAddresses: ["198.51.100.9"],
    rotationIndex: 0, lookup, nsecLookup: unsignedNsecLookup,
  });
  assert.ok(!asked.some((question) => question.endsWith(` ${firstSlice[6]}`) || question.endsWith(" api.example.com") || question.endsWith(" shop01.example.com")), "known names are never asked again"); checks++;
  assert.ok(asked.every((question) => question.startsWith("A ") || question.startsWith("AAAA ")), "lookups are address questions"); checks++;
  const askedAaaa = asked.filter((question) => question.startsWith("AAAA ")).map((question) => question.slice(5));
  assert.ok(!askedAaaa.includes(firstSlice[7]), "a name whose A answer is NXDOMAIN is not asked for AAAA"); checks++;
  assert.ok(askedAaaa.includes(firstSlice[3]) && askedAaaa.includes(firstSlice[4]), "a name A did not rule out is asked for AAAA"); checks++;
  assert.ok(!askedAaaa.includes(firstSlice[1]), "a guess A shows is the wildcard's answer is not asked for AAAA"); checks++;
  assert.equal(new Set(asked).size, asked.length, "no question is asked twice"); checks++;
  assert.equal(result.wordlist.checked, firstSlice.filter((name) => !known.includes(name)).length, "the slice is checked except for known names"); checks++;
  assert.ok(asked.length <= 2 * (limits.wordlistSlice + limits.variants), "lookups stay within the slice and variant bounds"); checks++;
  const sources = Object.fromEntries(result.confirmed.map((item) => [item.hostname, item.source]));
  assert.equal(sources[firstSlice[0]], "dns_wordlist", "a word-list name DNS answers for is confirmed"); checks++;
  assert.ok(!(firstSlice[1] in sources) && result.wordlist.wildcard_filtered === 1, "a guess answered exactly by the wildcard is not admitted"); checks++;
  assert.equal(result.confirmed.find((item) => item.hostname === firstSlice[2])?.alias_only, true, "an alias without an address is confirmed alias-only"); checks++;
  assert.equal(result.wordlist.no_address, 1, "NOERROR without an address is counted"); checks++;
  assert.equal(result.wordlist.lookup_failed, 2, "SERVFAIL and transport failures are counted"); checks++;
  assert.equal(sources["shop02.example.com"], "dns_name_variant", "a variant of a found host DNS answers for is confirmed"); checks++;
  assert.ok(result.variants.derived > 0 && result.variants.derived <= limits.variants, "variants stay within their bound"); checks++;
  assert.equal(result.nsec.outcome, "no_dnssec", "an unsigned zone stops the NSEC walk"); checks++;
  assert.equal(result.nsec.queries, 1, "an unsigned zone costs one NSEC question"); checks++;
  assert.ok(result.incomplete === true && result.incomplete_reason === "lookup_failed", "failed lookups leave the step incomplete"); checks++;

  // Both families: an IPv6-only guess is found with its address; a dual-stack
  // guess keeps both; a dangling alias is kept; one family failing never
  // erases the other's answer.
  const families = await api.runDiscoveryDepth("example.com", {
    rotationIndex: 0, nsecLookup: unsignedNsecLookup,
    lookup: async (name, type) => {
      if (name === firstSlice[0]) return type === "AAAA" ? answer6(name, "2001:db8::10") : { Status: 0, Answer: [] };
      if (name === firstSlice[1]) return type === "AAAA" ? answer6(name, "2001:db8::11") : answer(name, "203.0.113.11");
      if (name === firstSlice[2]) return { Status: 3, Answer: [{ name, type: 5, TTL: 60, data: "gone.provider.test." }] };
      if (name === firstSlice[3]) return type === "AAAA" ? { Status: 2, Answer: [] } : answer(name, "203.0.113.13");
      return nxdomain;
    },
  });
  const byName = Object.fromEntries(families.confirmed.map((item) => [item.hostname, item]));
  assert.deepEqual(byName[firstSlice[0]]?.ip_addresses, ["2001:db8::10"], "an IPv6-only guess is confirmed with its address"); checks++;
  assert.equal(byName[firstSlice[0]]?.dns?.A?.outcome, "nodata", "its A outcome is kept as NODATA"); checks++;
  assert.deepEqual(byName[firstSlice[1]]?.ip_addresses, ["203.0.113.11", "2001:db8::11"], "a dual-stack guess keeps both families"); checks++;
  assert.ok(byName[firstSlice[2]]?.alias_only === true && byName[firstSlice[2]]?.dangling_alias === true, "an alias whose target does not exist is kept as a dangling alias"); checks++;
  assert.deepEqual(byName[firstSlice[3]]?.ip_addresses, ["203.0.113.13"], "an A answer survives a failed AAAA question"); checks++;
  assert.deepEqual(byName[firstSlice[3]]?.dns?.uncertain, ["AAAA"], "the failed family is stated as uncertain"); checks++;
  assert.equal(families.wordlist.families?.ipv6_only ?? null, null, "per-family counts do not leak into the word-list tallies"); checks++;

  // The shared budget: questions beyond it are not asked, and say so.
  const { createDiscoveryQuestionBudget } = await eng("discovery-confirmation.js");
  const small = createDiscoveryQuestionBudget({ total: 30 });
  let budgetQuestions = 0;
  const budgeted = await api.runDiscoveryDepth("example.com", {
    rotationIndex: 0, budget: small, nsecLookup: async () => { budgetQuestions++; return { Status: 0, Answer: [] }; },
    lookup: async (name) => { budgetQuestions++; return name === firstSlice[0] ? answer(name, "203.0.113.50") : nxdomain; },
  });
  assert.ok(budgetQuestions <= 30 && small.snapshot().spent === budgetQuestions, "no question is asked beyond the shared budget"); checks++;
  assert.ok(budgeted.not_asked > 0 && (budgeted.incomplete_reasons || [budgeted.incomplete_reason]).includes("question_budget_reached"), "names the budget left unasked are stated"); checks++;

  // A sub-zone that answers every name: variants below it are not evidence.
  const subzone = await api.runDiscoveryDepth("example.com", {
    discoveredHosts: ["app01.preview.example.com"], rotationIndex: 0, nsecLookup: unsignedNsecLookup, random: () => 0.5,
    lookup: async (name, type) => (name.endsWith(".preview.example.com") && type === "A" ? answer(name, "203.0.113.99") : nxdomain),
  });
  assert.ok(!subzone.confirmed.some((item) => item.hostname.endsWith(".preview.example.com")), "variants answered by a sub-zone wildcard are not admitted"); checks++;
  assert.ok(subzone.variants.subzone_wildcards.some((item) => item.parent === "preview.example.com" && item.outcome === "wildcard"), "the sub-zone wildcard is stated"); checks++;

  // A signed zone: the walk lists names a word list would never guess, and a
  // name the word list also asks keeps the NSEC source and is never filtered.
  const guessedAndListed = wordlistRotation(5).labels[0];
  const signed = await api.runDiscoveryDepth("example.com", {
    knownHosts: [], wildcardAddresses: ["198.51.100.7"], rotationIndex: 5,
    lookup: async (name) => (name === "hidden.example.com" || name === `${guessedAndListed}.example.com`
      ? answer(name, "198.51.100.7")
      : name === "mail.example.com" ? answer(name, "203.0.113.25") : nxdomain),
    nsecLookup: nsecLookupFor(signedZoneOf(["hidden", "mail", guessedAndListed])),
  });
  assert.equal(signed.nsec.outcome, "complete", "a closed chain completes the walk"); checks++;
  assert.equal(signed.nsec.owners, 3, "the walk lists the zone's owner names"); checks++;
  const hidden = signed.confirmed.find((item) => item.hostname === "hidden.example.com");
  assert.ok(hidden?.source === "dnssec_nsec" && hidden.wildcard_match === true, "a listed name with a wildcard-shaped answer is flagged, not filtered"); checks++;
  assert.equal(signed.confirmed.find((item) => item.hostname === "mail.example.com")?.source, "dnssec_nsec", "names the zone lists keep the NSEC source"); checks++;
  const both = signed.confirmed.find((item) => item.hostname === `${guessedAndListed}.example.com`);
  assert.ok(both?.source === "dnssec_nsec" && both.wildcard_match === true,
    "a listed name the word list also asks keeps the NSEC source and is not wildcard-filtered"); checks++;
  assert.equal(signed.incomplete, false, "a clean signed run is complete"); checks++;

  // A long chain: the walk stops at its question bound and says so.
  const longZone = async (name) => {
    const index = name === "example.com" ? 0 : Number(name.match(/^n(\d+)\./)?.[1] ?? -1) + 1;
    return { Status: 0, AD: true, Answer: [nsecRecord(name, `n${String(index).padStart(3, "0")}.example.com`,
      name === "example.com" ? "A NS SOA RRSIG NSEC DNSKEY" : "A RRSIG NSEC")] };
  };
  let nsecQuestions = 0;
  const long = await api.runDiscoveryDepth("example.com", {
    lookup: async (name) => answer(name, "203.0.113.30"),
    nsecLookup: async (name) => { nsecQuestions++; return longZone(name); },
  });
  assert.equal(nsecQuestions, limits.nsecQueries, "the walk never asks more than its bound"); checks++;
  assert.equal(long.nsec.outcome, "budget_exhausted", "a walk stopped by its bound says so"); checks++;
  assert.ok(long.nsec.checked <= limits.nsecConfirmations, "listed names are confirmed within their bound"); checks++;
  assert.ok((long.incomplete_reasons || [long.incomplete_reason]).includes("nsec_budget_exhausted"), "an unfinished walk leaves the step incomplete"); checks++;

  // The soft budget: no new batch starts once it is spent.
  let ticks = 0;
  const slow = await api.runDiscoveryDepth("example.com", {
    clock: () => (ticks++ < 3 ? 0 : limits.softBudgetMs + 1),
    lookup: async (name) => answer(name, "203.0.113.40"),
    nsecLookup: unsignedNsecLookup,
  });
  assert.ok(slow.not_asked > 0 && slow.wordlist.checked < limits.wordlistSlice, "a spent soft budget stops new lookups"); checks++;
  assert.ok((slow.incomplete_reasons || [slow.incomplete_reason]).includes("time_budget_reached"), "names left unasked are stated"); checks++;

  const skipped = api.discoveryDepthNotExecuted("invocation_not_durable");
  assert.ok(skipped.executed === false && skipped.incomplete === true && skipped.confirmed.length === 0, "a step that did not run claims nothing"); checks++;
  return checks;
}

// ── 1. The real module, then its mutants ────────────────────────────────────
const api = await import(pathToFileURL(modulePath).href);
try {
  pass += await fixtures(api);
} catch (error) {
  fail++;
  console.log(`FAIL discovery-depth fixtures — ${error.message}`);
}
ok("module issues no request except through the injected DNS lookups",
  !/\bfetch\s*\(|safeFetch|probeAsset/.test(moduleSource) &&
    (moduleSource.match(/dnsQuery\(/g) || []).length === 1 && (moduleSource.match(/dnsQueryDnssec\(/g) || []).length === 1);

// Relative imports become absolute file URLs; the helper can be swapped for a
// mutated copy so its rules are proven through this module's fixtures.
const helperPath = enginePath("discovery-confirmation.js");
const helperSource = fs.readFileSync(helperPath, "utf8");
const dataUrl = (source) => `data:text/javascript;base64,${Buffer.from(source).toString("base64")}`;
const absoluteImports = (source, overrides = {}) => source.replace(/from "\.\/([^"]+)"/g,
  (_, file) => `from "${overrides[file] ?? pathToFileURL(enginePath(file)).href}"`);
const MUTANTS = [
  ["module", "const wordlist = tally(sliceRun.observations, DISCOVERY_DEPTH_ASSET_SOURCES.wordlist, { wildcardFor: () => apexWildcard, filterWildcard: true, listed });",
    "const wordlist = tally(sliceRun.observations, DISCOVERY_DEPTH_ASSET_SOURCES.wordlist, { wildcardFor: () => apexWildcard, filterWildcard: false, listed });", "wildcard guesses are admitted"],
  ["module", "filterWildcard: filterWildcard && !isListed,", "filterWildcard,", "a listed name asked by a guess is wildcard-filtered"],
  ["module", "source: isListed ? DISCOVERY_DEPTH_ASSET_SOURCES.nsec : source,", "source,", "a listed name asked by a guess loses its NSEC source"],
  ["module", "if (!name || asked.has(name)) continue;", "if (!name) continue;", "known names are asked again"],
  ["module", "const cursor = (index * size) % DISCOVERY_WORDLIST.length;", "const cursor = 0;", "the slice never rotates"],
  ["module", "[\"budget_exhausted\", \"lookup_failed\"", "[\"lookup_failed\"", "an unfinished walk is hidden"],
  ["module", "if (confirmation.status === \"confirmed\") {", "if (confirmation.status !== \"not_found\") {", "unconfirmed guesses are admitted"],
  ["helper", "if (wildcardMatch && filterWildcard) return { status: \"wildcard_filtered\", dns };", "", "the shared rule admits wildcard guesses"],
  ["helper", "if (positive || alias || dangling) {", "if (positive || alias || dangling || A.outcome === \"nodata\") {", "the shared rule admits names without an answer"],
  ["helper", "if (clock() >= deadlineAt) { unaskedTime += list.length - start; break; }", "", "the shared batches ignore the soft budget"],
  ["helper", "try { response = await lookup(hostname, type); } catch (err) { error = err ?? new Error(\"lookup_failed\"); }",
    "try { response = await lookup(hostname, type); } catch { response = { Status: 3, Answer: [] }; }", "the shared rule reads a failed lookup as absence"],
  ["helper", "alias_only: !positive,", "alias_only: false,", "the shared rule hides alias-only answers"],
  ["helper", "return { hostname, A, AAAA: await ask(lookup, hostname, \"AAAA\"), aaaa_skipped: null };",
    "return { hostname, A, AAAA: null, aaaa_skipped: null };", "guesses are never asked for AAAA"],
  ["helper", "? { outcome: \"dangling_alias\", addresses: [] }", "? { outcome: \"nxdomain\", addresses: [] }", "a dangling alias is dropped as absent"],
  ["helper", "if (budget && !budget.take(source, 1)) return { hostname, A: null, AAAA: null, not_asked: \"budget\" };", "", "guesses ignore the shared budget"],
  ["module", "return (parent && subzones.results.get(parent)) || apexWildcard;", "return apexWildcard;", "variants under a sub-zone wildcard are admitted"],
];
for (const [target, before, after, label] of MUTANTS) {
  const source = target === "helper" ? helperSource : moduleSource;
  ok(`mutant anchor is unique: ${label}`, source.split(before).length === 2);
  let killed = false;
  try {
    const mutated = target === "helper"
      ? absoluteImports(moduleSource, { "discovery-confirmation.js": dataUrl(absoluteImports(helperSource.replace(before, after))) })
      : absoluteImports(moduleSource.replace(before, after));
    await fixtures(await import(dataUrl(mutated)));
  } catch (error) {
    killed = error instanceof assert.AssertionError;
  }
  ok(`mutant rejected: ${label}`, killed);
}

// ── 2. Downstream contracts ─────────────────────────────────────────────────
const { assetSourceLabel } = await import(pathToFileURL(path.join(root, "frontend", "src", "lib", "assetSourceLabel.js")).href);
for (const code of Object.values(api.DISCOVERY_DEPTH_ASSET_SOURCES)) {
  ok(`asset source ${code} has customer wording`, assetSourceLabel(code) !== code && assetSourceLabel(code) !== "—", assetSourceLabel(code));
}
const shadowSource = fs.readFileSync(enginePath("shadow-it-inventory.js"), "utf8");
ok("Shadow IT treats every depth asset source as discovery evidence",
  /const DISCOVERY_ASSET_SOURCES = new Set\(\[[^\]]*?\.\.\.Object\.values\(DISCOVERY_DEPTH_ASSET_SOURCES\),[^\]]*\]\);/.test(shadowSource));
const { OUTBOUND_FULLY_INSTRUMENTED_MODULES } = await eng("scan-budget.js");
ok("the depth step's outbound calls are fully instrumented", OUTBOUND_FULLY_INSTRUMENTED_MODULES.has("discovery_depth"));
const db = { prepare: (sql) => ({ bind: (...args) => ({ first: async () => {
  assert.match(sql, /FROM scans WHERE domain_id = \? AND workspace_id = \? AND status = 'completed'/);
  assert.deepEqual(args, ["dom_1", "ws_1"]);
  return { n: 4 };
} }) }) };
const rotation = await api.loadDiscoveryRotationIndex({ cybermeters_db: db }, { domainId: "dom_1", workspaceId: "ws_1" });
ok("the rotation index is the workspace's completed scans of the domain", rotation.index === 4 && rotation.source === "completed_scans", JSON.stringify(rotation));
const brokenRotation = await api.loadDiscoveryRotationIndex({ cybermeters_db: { prepare: () => { throw new Error("d1 down"); } } }, { domainId: "dom_1", workspaceId: "ws_1" });
ok("a failed rotation read starts at the top and says so", brokenRotation.index === 0 && brokenRotation.source === "unavailable", JSON.stringify(brokenRotation));

// ── 3. Real engine traces ───────────────────────────────────────────────────
const { runScanEngine } = await eng("scan-engine.js");
const realFetch = globalThis.fetch;
const { DISCOVERY_WORDLIST } = await eng("discovery-wordlist.js");
const rotationOneName = `${api.wordlistRotation(1).labels[0]}.example.com`;

async function traceEngine(executionContext, { failWildcard = false } = {}) {
  const dnsQuestions = [];
  const inserts = [];
  let report = null;
  globalThis.fetch = async (input) => {
    const url = new URL(String(input));
    if (url.hostname === "cloudflare-dns.com" || url.hostname === "dns.google") {
      const name = url.searchParams.get("name") || "";
      const type = url.searchParams.get("type") || "A";
      dnsQuestions.push(`${type} ${name}${url.searchParams.get("do") === "1" ? " do" : ""}`);
      if (failWildcard && name.startsWith("cybermeters-wildcard-check-")) return Response.json({ Status: 2, Answer: [] });
      if (type === "NSEC") return Response.json(signedZone.has(name) ? { Status: 0, AD: true, Answer: [signedZone.get(name)] } : { Status: 0, Answer: [] });
      if (type === "A" && ["example.com", "www.example.com", "api.example.com", rotationOneName, "api-dev.example.com", "hidden.example.com"].includes(name)) {
        return Response.json({ Status: 0, Answer: [{ name, type: 1, TTL: 60, data: "203.0.113.50" }] });
      }
      return Response.json({ Status: 3, Answer: [] });
    }
    if (url.protocol === "https:" || url.protocol === "http:") {
      return new Response("<html><title>Site</title></html>", { status: 200, headers: { "content-type": "text/html" } });
    }
    return Response.json({});
  };
  const r2 = new Map();
  const statement = (sql, args = []) => ({
    sql,
    args,
    bind: (...bound) => statement(sql, bound),
    run: async () => ({ success: true, meta: { changes: /INSERT OR IGNORE INTO scan_report_snapshots|SET status = 'completed'/.test(sql) ? 1 : 0 } }),
    all: async () => ({ results: /FROM workspace_domains wd\s+JOIN workspaces w/.test(sql) ? [{ workspace_id: "ws_depth" }] : [] }),
    first: async () => (/SELECT id FROM workspaces WHERE id = \? AND deleted_at IS NULL/.test(sql) ? { id: args[0] }
      : /SELECT COUNT\(\*\) AS n FROM scans WHERE domain_id = \? AND workspace_id = \?/.test(sql) ? { n: 1 } : null),
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
        if (String(key) === "reports/scan_depth.json") report = JSON.parse(String(body));
        return {};
      },
      get: async (key) => (r2.has(String(key)) ? { text: async () => r2.get(String(key)), json: async () => JSON.parse(r2.get(String(key))) } : null),
      delete: async () => ({}),
    },
    APP_VERSION: "test",
  };
  let threw = null;
  try {
    await runScanEngine("scan_depth", "dom_depth", "ws_depth", "example.com", env, { executionContext });
  } catch (error) { threw = error; }
  globalThis.fetch = realFetch;
  return { threw, report, dnsQuestions, inserts };
}

const durable = await traceEngine("queue");
const depth = durable.report?.modules?.subdomains?.discovery_depth;
ok("durable trace completes", durable.threw === null && durable.report !== null, String(durable.threw));
ok("durable: the depth step ran on the second slice", depth?.executed === true && depth?.wordlist?.cursor === 200 &&
  depth?.wordlist?.rotation_source === "completed_scans", JSON.stringify(depth?.wordlist));
ok("durable: word-list, variant and listed names are confirmed with their source",
  JSON.stringify((depth?.confirmed || []).map((item) => [item.hostname, item.source]).sort()) === JSON.stringify([
    ["api-dev.example.com", "dns_name_variant"],
    ["hidden.example.com", "dnssec_nsec"],
    [rotationOneName, "dns_wordlist"],
  ].sort()), JSON.stringify(depth?.confirmed));
ok("durable: confirmed names join the discovered set",
  ["api-dev.example.com", "hidden.example.com", rotationOneName].every((host) => (durable.report?.modules?.subdomains?.items || []).includes(host)),
  JSON.stringify(durable.report?.modules?.subdomains?.items));
ok("durable: takeover checks the confirmed names",
  ["api-dev.example.com", "hidden.example.com", rotationOneName].every((host) => durable.dnsQuestions.includes(`CNAME ${host}`)));
ok("durable: the inventory records each confirmed name with its source",
  durable.inserts.some((row) => row.hostname === "hidden.example.com" && row.source === "dnssec_nsec") &&
    durable.inserts.some((row) => row.hostname === "api-dev.example.com" && row.source === "dns_name_variant") &&
    durable.inserts.some((row) => row.hostname === rotationOneName && row.source === "dns_wordlist"),
  JSON.stringify(durable.inserts));
ok("durable: NSEC questions carry the DNSSEC OK bit", durable.dnsQuestions.filter((q) => q.startsWith("NSEC ")).every((q) => q.endsWith(" do")) &&
  durable.dnsQuestions.some((q) => q.startsWith("NSEC ")));
const depthRow = (durable.report?.execution_diagnostics?.modules || []).find((row) => row?.module === "discovery_depth");
ok("durable: the depth step has its own measured telemetry row", depthRow?.outbound_measurement_complete === true, JSON.stringify(depthRow));
ok("durable: discovery names the depth step as a source",
  (durable.report?.modules?.attack_surface_signal_completeness?.signals?.subdomain_discovery?.sources || []).includes("discovery_depth"));

const compact = await traceEngine("waituntil");
ok("waitUntil: the step states it did not run", compact.report?.modules?.subdomains?.discovery_depth?.reason === "invocation_not_durable");
ok("waitUntil: no NSEC question and no rotating word-list name is asked",
  !compact.dnsQuestions.some((q) => q.startsWith("NSEC ") || q === `A ${rotationOneName}`));

const noWildcard = await traceEngine("queue", { failWildcard: true });
ok("an unfinished wildcard check runs no guesses",
  noWildcard.report?.modules?.subdomains?.discovery_depth?.reason === "wildcard_check_incomplete" &&
    !noWildcard.dnsQuestions.some((q) => q.startsWith("NSEC ") || q === `A ${rotationOneName}`),
  JSON.stringify(noWildcard.report?.modules?.subdomains?.discovery_depth));
ok("the authored list is the rotation source", DISCOVERY_WORDLIST.length > 2000);

console.log(`\ndiscovery depth: ${pass} passed, ${fail} failed`);
process.exit(fail === 0 ? 0 : 1);
