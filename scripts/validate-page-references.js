#!/usr/bin/env node
//
// Page references: hostnames under the domain that the site's own robots.txt,
// sitemaps and first-party scripts name, read by page discovery and confirmed
// by DNS after it. Deterministic: a fake site through safeFetch's fetchImpl
// seam, injected DNS, and the real scan engine against mocked fetch/D1/R2.
//
// Proves: page discovery reports in-scope names from the files it already
// reads (no extra request); other domains, the root and malformed names never
// become candidates; confirmation is one DNS question per name, at most 50,
// admits only names DNS answers for, flags rather than filters wildcard-shaped
// answers and counts everything else; a durable scan records confirmed names
// in the inventory with their specific source and names the step as a
// discovery source; the waitUntil path runs no lookup.
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const enginePath = (file) => path.join(root, "workers", "scan-api", "src", "engines", file);
const eng = (file) => import(pathToFileURL(enginePath(file)).href);
const modulePath = enginePath("page-references.js");
const moduleSource = fs.readFileSync(modulePath, "utf8");

let pass = 0, fail = 0;
const ok = (name, condition, detail = "") => {
  if (condition) pass++;
  else { fail++; console.log(`FAIL ${name}${detail ? ` — ${detail}` : ""}`); }
};

// ── 1. Page discovery reads references from the files it already fetches ────
const { runPageDiscoveryModule } = await eng("page-discovery.js");
function site(routes, log) {
  return async (url) => {
    log.push(url);
    const u = new URL(url);
    const r = routes[`${u.host}${u.pathname}`];
    const res = r
      ? new Response(r.body, { status: 200, headers: { "content-type": r.type ?? "text/html" } })
      : new Response("not found", { status: 404, headers: { "content-type": "text/html" } });
    Object.defineProperty(res, "url", { value: url });
    return res;
  };
}
const ROUTES = {
  "acme.test/": { body: `<html><a href="/about">About</a><script src="/app.js"></script></html>` },
  "acme.test/about": { body: "<html>About</html>" },
  "acme.test/robots.txt": { type: "text/plain", body: "User-agent: *\nDisallow: https://legacy.acme.test/admin\nSitemap: https://acme.test/sitemap.xml\nAllow: https://partner.example/x" },
  "acme.test/sitemap.xml": { type: "application/xml", body: "<urlset><url><loc>https://acme.test/about</loc></url><url><loc>https://shop.acme.test/</loc></url><url><loc>https://evil.example/</loc></url></urlset>" },
  "acme.test/app.js": { type: "application/javascript", body: `fetch("https://api.acme.test/v1/items"); const cdn = "assets.acme.test"; const x = "https://tracker.example/p";` },
};
const log = [];
const discovery = await runPageDiscoveryModule("acme.test", { fetchImpl: site(ROUTES, log) });
const refs = discovery.hostname_references;
ok("page discovery reports in-scope names with where they were named",
  JSON.stringify(refs?.candidates) === JSON.stringify([
    { hostname: "api.acme.test", sources: ["javascript"] },
    { hostname: "assets.acme.test", sources: ["javascript"] },
    { hostname: "legacy.acme.test", sources: ["robots_txt"] },
    { hostname: "shop.acme.test", sources: ["sitemap"] },
  ]), JSON.stringify(refs));
ok("references never include other domains or the root",
  !JSON.stringify(refs).includes("example") && !(refs?.candidates || []).some((c) => c.hostname === "acme.test"));
ok("reading references makes no extra request", log.every((url) => /acme\.test\//.test(url)) &&
  new Set(log.map((url) => new URL(url).pathname)).size === log.length - log.filter((url) => new URL(url).pathname === "/").length + 1);

// ── 2. Confirmation ─────────────────────────────────────────────────────────
const answer = (name, ip) => ({ Status: 0, Answer: [{ name, type: 1, TTL: 60, data: ip }] });
async function fixtures(api) {
  let checks = 0;
  const pending = api.pendingPageReferences("acme.test", {
    candidates: [
      { hostname: "assets.acme.test", sources: ["javascript"] },
      { hostname: "legacy.acme.test", sources: ["robots_txt"] },
      { hostname: "shop.acme.test", sources: ["sitemap", "javascript"] },
      { hostname: "known.acme.test", sources: ["sitemap"] },
      { hostname: "acme.test", sources: ["sitemap"] },
      { hostname: "other.example", sources: ["sitemap"] },
      { hostname: "odd.acme.test", sources: ["unknown_source"] },
    ],
  }, ["known.acme.test"]);
  assert.deepEqual(pending.map((p) => p.hostname), ["legacy.acme.test", "shop.acme.test", "assets.acme.test"],
    "pending: in-scope, unknown names only, robots before sitemap before scripts"); checks++;
  const asked = [];
  const result = await api.confirmPageReferences(pending, {
    wildcardAddresses: ["198.51.100.9"],
    lookup: async (name) => {
      asked.push(name);
      if (name === "assets.acme.test") throw new Error("network down");
      return name === "legacy.acme.test" ? answer(name, "198.51.100.9") : answer(name, "203.0.113.90");
    },
  });
  assert.deepEqual(asked, ["legacy.acme.test", "shop.acme.test", "assets.acme.test"], "one question per pending name"); checks++;
  assert.deepEqual(result.confirmed.map((item) => [item.hostname, item.asset_source]),
    [["legacy.acme.test", "robots_reference"], ["shop.acme.test", "sitemap_reference"]], "confirmed names keep their most specific source"); checks++;
  assert.equal(result.confirmed[0].wildcard_match, true, "a wildcard-shaped answer is flagged, not filtered"); checks++;
  assert.ok(result.lookup_failed === 1 && result.incomplete_reason === "lookup_failed", "a failed lookup is counted and leaves the step incomplete"); checks++;
  const many = Array.from({ length: 70 }, (_, i) => ({ hostname: `n${i}.acme.test`, sources: ["javascript"] }));
  let questions = 0;
  const capped = await api.confirmPageReferences(many, { lookup: async (name) => { questions++; return answer(name, "203.0.113.91"); } });
  assert.ok(questions === 50 && capped.not_checked === 20 && capped.incomplete_reason === "check_cap_reached", "at most 50 questions; the rest are counted"); checks++;
  const none = api.pageReferencesNotExecuted("no_references");
  assert.ok(none.incomplete === false && none.confirmed.length === 0, "no references is not a gap"); checks++;
  assert.equal(api.pageReferencesNotExecuted("invocation_not_durable").incomplete, true, "a step that did not run says so"); checks++;
  return checks;
}
const api = await import(pathToFileURL(modulePath).href);
try { pass += await fixtures(api); } catch (error) { fail++; console.log(`FAIL page-reference fixtures — ${error.message}`); }

const dataUrl = (source) => `data:text/javascript;base64,${Buffer.from(source).toString("base64")}`;
const absoluteImports = (source) => source.replace(/from "\.\/([^"]+)"/g, (_, file) => `from "${pathToFileURL(enginePath(file)).href}"`);
const MUTANTS = [
  ["const checks = list.slice(0, PAGE_REFERENCE_LIMITS.maxChecks);", "const checks = list;", "the lookup cap is removed"],
  ["const confirmation = confirmationOf(observations[index], { wildcardSet, filterWildcard: false });",
    "const confirmation = confirmationOf(observations[index], { wildcardSet, filterWildcard: true });", "named names are wildcard-filtered"],
  ["if (!root || !hostname || hostname === root || !hostname.endsWith(`.${root}`) || seen.has(hostname)) continue;",
    "if (!hostname || seen.has(hostname)) continue;", "the scope guard is removed"],
  ["if (counts.lookup_failed > 0) reasons.push(\"lookup_failed\");", "", "failed lookups are hidden"],
  ["  robots_txt: \"robots_reference\",\n  sitemap:    \"sitemap_reference\",", "  sitemap:    \"sitemap_reference\",\n  robots_txt: \"robots_reference\",", "source precedence is reordered"],
];
for (const [before, after, label] of MUTANTS) {
  ok(`mutant anchor is unique: ${label}`, moduleSource.split(before).length === 2);
  let killed = false;
  try { await fixtures(await import(dataUrl(absoluteImports(moduleSource.replace(before, after))))); }
  catch (error) { killed = error instanceof assert.AssertionError; }
  ok(`mutant rejected: ${label}`, killed);
}

// ── 3. Downstream contracts ─────────────────────────────────────────────────
const { assetSourceLabel } = await import(pathToFileURL(path.join(root, "frontend", "src", "lib", "assetSourceLabel.js")).href);
for (const code of Object.values(api.PAGE_REFERENCE_ASSET_SOURCES)) {
  ok(`asset source ${code} has customer wording`, assetSourceLabel(code) !== code && assetSourceLabel(code) !== "—");
}
const shadow = fs.readFileSync(enginePath("shadow-it-inventory.js"), "utf8");
ok("Shadow IT treats page references as discovery evidence",
  /const DISCOVERY_ASSET_SOURCES = new Set\(\[[^\]]*\.\.\.Object\.values\(PAGE_REFERENCE_ASSET_SOURCES\),[^\]]*\]\);/.test(shadow));
const { OUTBOUND_FULLY_INSTRUMENTED_MODULES } = await eng("scan-budget.js");
ok("the confirmation step's outbound calls are fully instrumented", OUTBOUND_FULLY_INSTRUMENTED_MODULES.has("page_references"));

// ── 4. Real engine traces ───────────────────────────────────────────────────
const { runScanEngine } = await eng("scan-engine.js");
const realFetch = globalThis.fetch;
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
      if (["acme.test", "www.acme.test", "ledger9.acme.test"].includes(name)) {
        return Response.json({ Status: 0, Answer: type === "A" ? [{ name, type: 1, TTL: 60, data: "93.184.216.34" }] : [] });
      }
      return Response.json({ Status: 3, Answer: [] });
    }
    if (url.protocol === "https:" || url.protocol === "http:") {
      const body = url.pathname === "/robots.txt" ? "User-agent: *\nDisallow: https://ledger9.acme.test/x\nDisallow: https://gone7.acme.test/y"
        : url.pathname === "/" ? "<html><title>Site</title><a href='/about'>About</a></html>" : "<html>page</html>";
      const res = new Response(body, { status: url.pathname === "/" || url.pathname === "/robots.txt" || url.pathname === "/about" ? 200 : 404,
        headers: { "content-type": url.pathname === "/robots.txt" ? "text/plain" : "text/html" } });
      Object.defineProperty(res, "url", { value: String(input) });
      return res;
    }
    return Response.json({});
  };
  const r2 = new Map();
  const statement = (sql, args = []) => ({
    sql, args,
    bind: (...bound) => statement(sql, bound),
    run: async () => ({ success: true, meta: { changes: /INSERT OR IGNORE INTO scan_report_snapshots|SET status = 'completed'/.test(sql) ? 1 : 0 } }),
    all: async () => ({ results: /FROM workspace_domains wd\s+JOIN workspaces w/.test(sql) ? [{ workspace_id: "ws_pr" }] : [] }),
    first: async () => (/SELECT id FROM workspaces WHERE id = \? AND deleted_at IS NULL/.test(sql) ? { id: args[0] } : null),
  });
  const env = {
    cybermeters_db: {
      prepare: (sql) => statement(sql),
      batch: async (statements) => {
        for (const item of statements) if (/INSERT OR IGNORE INTO workspace_assets/.test(item.sql)) inserts.push({ hostname: item.args[3], source: item.args[5] });
        return statements.map(() => ({ results: [], success: true, meta: { changes: 0 } }));
      },
    },
    cybermeters_reports: {
      put: async (key, body) => { r2.set(String(key), String(body)); if (String(key) === "reports/scan_pr.json") report = JSON.parse(String(body)); return {}; },
      get: async (key) => (r2.has(String(key)) ? { text: async () => r2.get(String(key)), json: async () => JSON.parse(r2.get(String(key))) } : null),
      delete: async () => ({}),
    },
    APP_VERSION: "test",
  };
  let threw = null;
  try { await runScanEngine("scan_pr", "dom_pr", "ws_pr", "acme.test", env, { executionContext }); } catch (error) { threw = error; }
  globalThis.fetch = realFetch;
  return { threw, report, dnsQuestions, inserts };
}
const durable = await traceEngine("queue");
const step = durable.report?.modules?.subdomains?.page_references;
ok("durable trace completes", durable.threw === null && durable.report !== null, String(durable.threw));
ok("durable: a robots.txt name DNS answers for is confirmed; one that does not exist is counted",
  JSON.stringify(step?.confirmed?.map((item) => [item.hostname, item.asset_source])) === JSON.stringify([["ledger9.acme.test", "robots_reference"]]) &&
    step?.not_found === 1, JSON.stringify(step));
ok("durable: the inventory records it with its source",
  durable.inserts.some((row) => row.hostname === "ledger9.acme.test" && row.source === "robots_reference") &&
    !durable.inserts.some((row) => row.hostname === "gone7.acme.test"), JSON.stringify(durable.inserts));
const signal = durable.report?.modules?.attack_surface_signal_completeness?.signals?.subdomain_discovery;
ok("durable: discovery names the step and counts the confirmed name",
  (signal?.sources || []).includes("page_references") && signal?.state === "observed", JSON.stringify(signal));
const compact = await traceEngine("waituntil");
ok("waitUntil: no reference is looked up and the step says why",
  compact.report?.modules?.subdomains?.page_references?.reason === "invocation_not_durable" &&
    !compact.dnsQuestions.includes("A ledger9.acme.test"));

console.log(`\npage references: ${pass} passed, ${fail} failed`);
process.exit(fail === 0 ? 0 : 1);
