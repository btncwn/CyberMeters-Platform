#!/usr/bin/env node
//
// Website Security — bounded important-page discovery (engine). Deterministic
// fixtures over a fake site served through safeFetch's fetchImpl seam; no
// network. CI-blocking.
//
// Proves: same-site scope (no other host is ever fetched or parsed), hard
// bounds (pages, fetches, bytes), soft-404 and off-site redirect handling,
// "not_found" only for an actually requested 404/410, per-page observations
// (headers, cookie flags WITHOUT values, forms, mixed content, third-party
// scripts, sensitive classification), and that the module never sets the
// scan-wide `incomplete` flag.
import fs from "node:fs";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const src = (...p) => pathToFileURL(path.join(root, "workers", "scan-api", "src", ...p)).href;
const pd = await import(src("engines", "page-discovery.js"));
const { persistWebsitePagesForScan, listWebsitePages, projectObservation } = await import(src("engines", "website-pages.js"));
const { websiteSecurityRoutes } = await import(src("routes", "website-security.js"));
const { runScanEngine } = await import(src("engines", "scan-engine.js"));
const {
  runPageDiscoveryModule, PAGE_DISCOVERY_LIMITS, siteHosts, normalizePath, classifySensitivePath,
  toSameSitePageUrl, extractLinks, parseRobotsSitemaps, parseSitemap, parseCookieFlags, extractForms,
  findMixedContent, thirdPartyScriptHosts, forEachTag, hasPasswordField,
  extractJsPaths, firstPartyScriptUrls, isRequestablePath, isApiPath, pathWords,
} = pd;

let pass = 0, fail = 0;
const ok = (name, cond, detail = "") => {
  if (cond) pass++;
  else { fail++; console.error(`FAIL ${name}${detail ? ` — ${detail}` : ""}`); }
};
const eq = (name, got, want) => ok(name, JSON.stringify(got) === JSON.stringify(want), `got ${JSON.stringify(got)} want ${JSON.stringify(want)}`);

// ── 1. Pure helpers ─────────────────────────────────────────────────────────
const hosts = siteHosts("acme.test");
eq("siteHosts: apex + www", [...hosts].sort(), ["acme.test", "www.acme.test"]);
eq("siteHosts from www", [...siteHosts("www.acme.test")].sort(), ["acme.test", "www.acme.test"]);
eq("normalizePath strips trailing slash/query", normalizePath("/Login/"), "/Login");
eq("normalizePath root", normalizePath(""), "/");
eq("sensitive: login", classifySensitivePath("/wp-login.php"), "login");
eq("sensitive: admin", classifySensitivePath("/admin"), "admin");
eq("sensitive: checkout", classifySensitivePath("/shop/checkout"), "checkout");
eq("sensitive: account", classifySensitivePath("/my-account"), "account");
eq("sensitive: ordinary", classifySensitivePath("/about-us"), null);
const base = "https://acme.test/";
ok("same-site: relative link kept", toSameSitePageUrl("/pricing?x=1#a", base, hosts)?.toString() === "https://acme.test/pricing");
ok("same-site: www sibling kept", !!toSameSitePageUrl("https://www.acme.test/contact", base, hosts));
ok("same-site: other host dropped", toSameSitePageUrl("https://evil.example/login", base, hosts) === null);
ok("same-site: other subdomain dropped", toSameSitePageUrl("https://shop.acme.test/", base, hosts) === null);
ok("same-site: credentials dropped", toSameSitePageUrl("https://u:p@acme.test/", base, hosts) === null);
ok("same-site: mailto/javascript dropped", [toSameSitePageUrl("mailto:a@acme.test", base, hosts), toSameSitePageUrl("javascript:alert(1)", base, hosts)].every((v) => v === null));
ok("same-site: static asset dropped", toSameSitePageUrl("/logo.png", base, hosts) === null);
ok("same-site: odd port dropped", toSameSitePageUrl("https://acme.test:8443/admin", base, hosts) === null);
eq("extractLinks", extractLinks(`<a href="/a">a</a><A HREF='/b'>b</A><a name=x>`), ["/a", "/b"]);
eq("robots sitemaps", parseRobotsSitemaps("User-agent: *\nSitemap: https://acme.test/sm.xml\nsitemap:/x.xml"), ["https://acme.test/sm.xml", "/x.xml"]);
eq("sitemap urlset", parseSitemap("<urlset><url><loc> https://acme.test/a </loc></url><url><loc>https://acme.test/b?x=1&amp;y=2</loc></url></urlset>"),
  { isIndex: false, locs: ["https://acme.test/a", "https://acme.test/b?x=1&y=2"] });
ok("sitemap index detected", parseSitemap("<sitemapindex><sitemap><loc>https://acme.test/s1.xml</loc></sitemap></sitemapindex>").isIndex);
const cookies = parseCookieFlags(["sid=SECRETVALUE; Path=/; HttpOnly", "pref=dark; Secure; SameSite=Lax"]);
eq("cookie flags", cookies, [
  { name: "sid", secure: false, httponly: true, samesite: null },
  { name: "pref", secure: true, httponly: false, samesite: "lax" },
]);
ok("cookie values are never retained", !JSON.stringify(cookies).includes("SECRETVALUE") && !JSON.stringify(cookies).includes("dark"));
const forms = extractForms(
  `<form method="post" action="https://collector.example/x"><input type="password" name=p></form>
   <form action="http://acme.test/subscribe"><input name=e></form><form method=POST><input type='password'></form>`,
  "https://acme.test/login", hosts);
eq("forms: other origin with password", forms[0], { method: "post", action_kind: "other_origin", action_scheme: "https", action_host: "collector.example", has_password: true });
eq("forms: same-site over http", [forms[1].action_kind, forms[1].action_scheme], ["same_origin", "http"]);
eq("forms: implicit action inherits page scheme", [forms[2].action_kind, forms[2].action_scheme, forms[2].has_password], ["same_origin", "https", true]);
eq("mixed content on https", findMixedContent(`<script src="http://cdn.old/x.js"></script><img src='http://img.example/a.png'><link rel=stylesheet href="http://css.example/s.css"><a href="http://x">`, "https://acme.test/"),
  { count: 3, hosts: ["cdn.old", "img.example", "css.example"] });
eq("no mixed content on http page", findMixedContent(`<script src="http://cdn/x.js">`, "http://acme.test/").count, 0);
// nosemgrep: javascript.lang.security.audit.unknown-value-with-script-tag.unknown-value-with-script-tag -- INTENTIONAL: inert HTML fixture parsed (never rendered) by the scanner under test; `hosts` is a test-local Set.
eq("third-party scripts", thirdPartyScriptHosts(`<script src="/app.js"></script><script src="https://cdn.vendor.example/v.js"></script><script src="//www.acme.test/x.js"></script><script src="https://a.analytics.example/t.js">`, "https://acme.test/", hosts),
  ["a.analytics.example", "cdn.vendor.example"]);

// ── 2. Module over a fake site ─────────────────────────────────────────────
function site(routes, { log } = {}) {
  return async (url) => {
    log?.push(url);
    const u = new URL(url);
    const key = `${u.host}${u.pathname}`;
    const r = routes[key] ?? routes[`*${u.pathname}`];
    let res;
    if (!r) res = new Response("not found", { status: 404, headers: { "content-type": "text/html" } });
    else if (r.redirect) res = new Response(null, { status: 301, headers: { location: r.redirect } });
    else {
      const h = new Headers({ "content-type": r.type ?? "text/html; charset=utf-8", ...(r.headers || {}) });
      for (const c of r.cookies || []) h.append("set-cookie", c);
      res = new Response(r.body ?? "", { status: r.status ?? 200, headers: h });
    }
    Object.defineProperty(res, "url", { value: url });
    return res;
  };
}
const HOME = `<html><body>
  <a href="/about">About</a><a href="/login">Sign in</a><a href="https://other.example/login">x</a>
  <a href="/old-page">Old</a><a href="/promo">Promo</a><a href="/go-elsewhere">Partner</a>
  <script src="https://cdn.vendor.example/a.js"></script></body></html>`;
const LOGIN = `<html><form method="post" action="https://collector.example/auth"><input type="password" name="pw"></form>
  <script src="http://legacy.example/old.js"></script></html>`;
const baseRoutes = {
  "acme.test/": { body: HOME, headers: { "strict-transport-security": "max-age=31536000" } },
  "acme.test/about": { body: "<html>About us</html>" },
  "acme.test/login": { body: LOGIN, cookies: ["session=abc123; Path=/"] },
  "acme.test/promo": { redirect: "https://acme.test/" },
  "acme.test/go-elsewhere": { redirect: "https://partner.example/landing" },
  "partner.example/landing": { body: "<html>partner</html>" },
  "acme.test/robots.txt": { type: "text/plain", body: "Sitemap: https://acme.test/sitemap.xml" },
  "acme.test/sitemap.xml": { type: "application/xml", body: "<urlset><url><loc>https://acme.test/checkout</loc></url><url><loc>https://evil.example/admin</loc></url></urlset>" },
  "acme.test/checkout": { body: "<html><form method=post action='/pay'></form></html>" },
};
{
  const log = [];
  const r = await runPageDiscoveryModule("acme.test", { fetchImpl: site(baseRoutes, { log }) });
  const byPath = Object.fromEntries(r.pages.map((p) => [p.path, p]));
  ok("module: never sets the scan-wide incomplete flag", !("incomplete" in r));
  eq("module: coverage complete", r.coverage, "complete");
  ok("module: homepage observed first", r.pages[0].path === "/" && r.pages[0].outcome === "observed");
  eq("module: homepage HSTS present", r.pages[0].security_headers.present.includes("strict-transport-security"), true);
  eq("login: sensitive + observed", [byPath["/login"]?.sensitive_kind, byPath["/login"]?.outcome], ["login", "observed"]);
  eq("login: off-site password form recorded", byPath["/login"].forms[0].action_host, "collector.example");
  eq("login: session cookie without Secure (no value)", byPath["/login"].cookies, [{ name: "session", secure: false, httponly: false, samesite: null }]);
  eq("login: mixed content counted", byPath["/login"].mixed_content.count, 1);
  eq("login: HSTS missing on login page", byPath["/login"].security_headers.missing.includes("strict-transport-security"), true);
  eq("sitemap page discovered and classified", [byPath["/checkout"]?.source, byPath["/checkout"]?.sensitive_kind], ["sitemap", "checkout"]);
  eq("old link that 404s → not_found (requested)", byPath["/old-page"]?.outcome, "not_found");
  eq("redirect to homepage → soft_404", byPath["/promo"]?.outcome, "soft_404");
  eq("off-site redirect → redirected_offsite, not parsed", [byPath["/go-elsewhere"]?.outcome, byPath["/go-elsewhere"]?.forms], ["redirected_offsite", undefined]);
  ok("never fetched another host except by following the site's own redirect",
    log.every((u) => /^https?:\/\/(www\.)?acme\.test\//.test(u) || u === "https://partner.example/landing"), JSON.stringify(log));
  ok("other-host links never fetched", !log.some((u) => u.includes("other.example") || u.includes("evil.example")));
  ok("homepage third-party scripts", r.pages[0].third_party_scripts.includes("cdn.vendor.example"));
  ok("cookie values never appear in the result", !JSON.stringify(r).includes("abc123"));
  ok("no raw HTML retained", !JSON.stringify(r).includes("<form") && !JSON.stringify(r).includes("<html"));
  ok("fetch count within limit", r.counts.fetched <= PAGE_DISCOVERY_LIMITS.maxFetches);
  // well-known probes only for kinds not already covered (login/checkout covered; admin/account probed)
  ok("well-known: covered kinds not re-probed", !log.includes("https://acme.test/signin") && !log.includes("https://acme.test/wp-login.php"));
  ok("well-known: uncovered kinds probed", log.includes("https://acme.test/admin") && log.includes("https://acme.test/account"));
  ok("well-known: probe 404s kept as not_found only", byPath["/admin"]?.outcome === "not_found");
}
{
  // Page and fetch bounds on a huge site.
  const routes = { "acme.test/": { body: Array.from({ length: 300 }, (_, i) => `<a href="/p${i}">p</a>`).join("") } };
  for (let i = 0; i < 300; i++) routes[`acme.test/p${i}`] = { body: `<html>page ${i}</html>` };
  const r = await runPageDiscoveryModule("acme.test", { fetchImpl: site(routes) });
  ok("bounds: pages capped", r.pages.length <= PAGE_DISCOVERY_LIMITS.maxPages, String(r.pages.length));
  ok("bounds: fetches capped", r.counts.fetched <= PAGE_DISCOVERY_LIMITS.maxFetches, String(r.counts.fetched));
  eq("bounds: coverage partial with page_limit", [r.coverage, r.partial_reasons.includes("page_limit")], ["partial", true]);
}
{
  // Body read is bounded.
  let served = 0;
  const big = "<a href='/x'>x</a>" + "A".repeat(5_000_000);
  const fetchImpl = async (url) => {
    const stream = new ReadableStream({
      pull(c) { const chunk = new TextEncoder().encode(big.slice(served, served + 65_536)); served += chunk.length; if (!chunk.length || served > big.length) c.close(); else c.enqueue(chunk); },
    });
    const res = new Response(new URL(url).pathname === "/" ? stream : "<html>x</html>", { headers: { "content-type": "text/html" } });
    Object.defineProperty(res, "url", { value: url });
    return res;
  };
  await runPageDiscoveryModule("acme.test", { fetchImpl });
  // Node's Response wrapper pre-buffers a few chunks; the point is that a 5 MB
  // body is abandoned near the cap instead of being read to the end.
  ok("bounds: homepage body read is abandoned near the byte cap", served < 1_048_576, String(served));
}
{
  // Time budget: no fetch launched when the remaining budget is too small.
  const log = [];
  const r = await runPageDiscoveryModule("acme.test", { fetchImpl: site(baseRoutes, { log }), remainingMs: () => 1_000 });
  eq("time budget: nothing fetched", log.length, 0);
  eq("time budget: not_run + reason", [r.coverage, r.partial_reasons.includes("time_budget")], ["not_run", true]);
  ok("time budget: still no incomplete flag", !("incomplete" in r));
}
{
  // Homepage that redirects off-site: nothing else is crawled.
  const log = [];
  const r = await runPageDiscoveryModule("acme.test", { fetchImpl: site({ "acme.test/": { redirect: "https://parked.example/" }, "parked.example/": { body: "<a href='/login'>" } }, { log }) });
  eq("offsite homepage: not_run", r.coverage, "not_run");
  ok("offsite homepage: parked host never crawled further", !log.some((u) => u.startsWith("https://parked.example/login")));
}
{
  // Homepage unavailable (5xx on both schemes) → not_run, no pages.
  const r = await runPageDiscoveryModule("acme.test", { fetchImpl: site({ "acme.test/": { status: 503 } }) });
  eq("homepage 5xx: not_run, no pages", [r.coverage, r.pages.length], ["not_run", 0]);
}
{
  // Private/reserved literal targets are refused by safeFetch even if linked.
  const log = [];
  await runPageDiscoveryModule("127.0.0.1", { fetchImpl: site({}, { log }) });
  eq("ssrf: loopback domain never fetched", log.length, 0);
}
{
  // Password field on an ordinary path marks the page as login.
  const r = await runPageDiscoveryModule("acme.test", { fetchImpl: site({
    "acme.test/": { body: "<a href='/members-area-x'>m</a><a href='/portal'>p</a>" },
    "acme.test/portal": { body: "<form method=post><input type=password></form>" },
  }) });
  const portal = r.pages.find((p) => p.path === "/portal");
  eq("password field → login by content", [portal?.sensitive_kind, portal?.sensitive_basis], ["login", "password_field"]);
}

{
  // The fetch bound binds on its own (tightened for the test), and limits can
  // never be loosened by a caller.
  const log = [];
  const r = await runPageDiscoveryModule("acme.test", { fetchImpl: site(baseRoutes, { log }), limits: { maxFetches: 4 } });
  eq("fetch bound: exactly the tightened number of fetches", log.length, 4);
  ok("fetch bound: partial with fetch_limit", r.partial_reasons.includes("fetch_limit"));
  const log2 = [];
  const routes = { "acme.test/": { body: Array.from({ length: 60 }, (_, i) => `<a href="/q${i}">q</a>`).join("") } };
  for (let i = 0; i < 60; i++) routes[`acme.test/q${i}`] = { body: `<html>q${i}</html>` };
  const r2 = await runPageDiscoveryModule("acme.test", { fetchImpl: site(routes, { log: log2 }), limits: { maxPages: 500, maxFetches: 500 } });
  ok("limits cannot be loosened", r2.pages.length <= PAGE_DISCOVERY_LIMITS.maxPages && log2.length <= PAGE_DISCOVERY_LIMITS.maxFetches, `${r2.pages.length}/${log2.length}`);
}
{
  // Soft-404 by redirect to the homepage even when the homepage content differs
  // per request (dynamic page), and by identical content without a redirect.
  let n = 0;
  const fetchImpl = async (url) => {
    const u = new URL(url);
    let res;
    if (u.pathname === "/") res = new Response(`<html>home ${n++}<a href="/gone">g</a><a href="/clone">c</a></html>`, { headers: { "content-type": "text/html" } });
    else if (u.pathname === "/gone") res = new Response(null, { status: 302, headers: { location: "/" } });
    else if (u.pathname === "/clone") res = new Response(`<html>home 0<a href="/gone">g</a><a href="/clone">c</a></html>`, { headers: { "content-type": "text/html" } });
    else res = new Response("nf", { status: 404, headers: { "content-type": "text/html" } });
    Object.defineProperty(res, "url", { value: url });
    return res;
  };
  const r = await runPageDiscoveryModule("acme.test", { fetchImpl });
  const by = Object.fromEntries(r.pages.map((p) => [p.path, p]));
  eq("soft-404: redirect to homepage (dynamic home)", [by["/gone"]?.outcome, by["/gone"]?.soft_404_basis], ["soft_404", "redirected_to_homepage"]);
  eq("soft-404: same content as homepage", [by["/clone"]?.outcome, by["/clone"]?.soft_404_basis], ["soft_404", "same_content_as_homepage"]);
}

// ── 3. Persistence (migration 115) ─────────────────────────────────────────
function createDb() {
  const db = new DatabaseSync(":memory:");
  db.exec(`
    CREATE TABLE workspaces (id TEXT PRIMARY KEY, owner_user_id TEXT, deleted_at TEXT);
    CREATE TABLE domains (id TEXT PRIMARY KEY, domain TEXT);
    CREATE TABLE workspace_domains (workspace_id TEXT, domain_id TEXT, verification_status TEXT);
  `);
  db.exec(fs.readFileSync(path.join(root, "database", "migrations", "115-website-page-inventory.sql"), "utf8"));
  db.prepare("INSERT INTO domains VALUES ('d1','acme.test')").run();
  for (const [ws, st] of [["ws_a", "verified"], ["ws_b", "verified"], ["ws_unv", "unverified"]]) {
    db.prepare("INSERT INTO workspaces VALUES (?,?,NULL)").run(ws, `owner_${ws}`);
    db.prepare("INSERT INTO workspace_domains VALUES (?,?,?)").run(ws, "d1", st);
  }
  return db;
}
function d1(db) {
  const stmt = (sql) => {
    const st = db.prepare(sql);
    const bound = (...a) => ({
      _run: () => st.run(...a),
      all: async () => ({ results: st.all(...a) }),
      first: async () => st.get(...a) ?? null,
      run: async () => ({ meta: { changes: Number(st.run(...a).changes) } }),
    });
    return { bind: (...a) => bound(...a), all: async () => bound().all(), first: async () => bound().first(), _run: () => bound()._run() };
  };
  return { prepare: stmt, async batch(list) { db.exec("BEGIN"); try { const r = list.map((x) => x._run()); db.exec("COMMIT"); return r; } catch (e) { db.exec("ROLLBACK"); throw e; } } };
}
const page = (p, outcome = "observed", extra = {}) => ({ path: p, outcome, source: "homepage_link", status_code: outcome === "not_found" ? 404 : 200,
  final_url: `https://acme.test${p}?token=SHOULD_NOT_PERSIST`, https: true, sensitive_kind: null,
  security_headers: { present: [], missing: ["strict-transport-security"] }, cookies: [{ name: "sid", secure: false, httponly: true, samesite: null, value: "LEAKED" }],
  forms: [], password_field: false, mixed_content: { count: 0, hosts: [] }, third_party_scripts: [], html: "<form>", ...extra });
const disc = (pages, coverage = "complete") => ({ source: "page_discovery", version: "t", coverage, partial_reasons: coverage === "partial" ? ["page_limit"] : [], counts: { fetched: pages.length }, limits: { max_pages: 15 }, pages });
const pageRow = (db, ws, p) => db.prepare("SELECT * FROM website_pages WHERE workspace_id = ? AND path = ?").get(ws, p);
const evts = (db, ws) => db.prepare("SELECT path, event_type FROM website_page_events WHERE workspace_id = ? ORDER BY path, event_type").all(ws).map((r) => `${r.path}:${r.event_type}`);
{
  const db = createDb(); const env = { cybermeters_db: d1(db) };
  const t1 = "2026-10-01T00:00:00.000Z", t2 = "2026-10-02T00:00:00.000Z", t3 = "2026-10-03T00:00:00.000Z";
  const r1 = await persistWebsitePagesForScan(env, { workspace_id: "ws_a", domain_id: "d1", domain: "acme.test", scan_id: "s1", now: t1,
    discovery: disc([page("/"), page("/login", "observed", { sensitive_kind: "login" }), page("/never-seen", "not_found"), page("/flaky", "soft_404")]) });
  eq("persist: only observed pages create rows", [r1.created, !!pageRow(db, "ws_a", "/never-seen"), !!pageRow(db, "ws_a", "/flaky")], [2, false, false]);
  eq("persist: first_seen events", evts(db, "ws_a"), ["/:page_first_seen", "/login:page_first_seen"]);
  const row = pageRow(db, "ws_a", "/login");
  eq("persist: sensitive kind and status", [row.sensitive_kind, row.monitoring_status, row.first_seen_at], ["login", "observed", t1]);
  ok("persist: no cookie value, no HTML, no query string", !/LEAKED|<form|SHOULD_NOT_PERSIST/.test(JSON.stringify(row)), JSON.stringify(row));
  eq("persist: run row recorded", db.prepare("SELECT coverage FROM website_page_discovery_runs WHERE workspace_id='ws_a'").all().map((r) => r.coverage), ["complete"]);
  // Scan 2: /login answers 404; "/" not requested at all.
  await persistWebsitePagesForScan(env, { workspace_id: "ws_a", domain_id: "d1", domain: "acme.test", scan_id: "s2", now: t2,
    discovery: disc([page("/login", "not_found")], "partial") });
  eq("not_found only when requested", [pageRow(db, "ws_a", "/login").monitoring_status, pageRow(db, "ws_a", "/").monitoring_status], ["not_found", "observed"]);
  eq("unrequested page untouched", pageRow(db, "ws_a", "/").last_checked_at, t1);
  eq("not_found keeps last_seen", pageRow(db, "ws_a", "/login").last_seen_at, t1);
  ok("page_not_found event", evts(db, "ws_a").includes("/login:page_not_found"));
  // Scan 3: /login back; error answer for "/" keeps its observation.
  await persistWebsitePagesForScan(env, { workspace_id: "ws_a", domain_id: "d1", domain: "acme.test", scan_id: "s3", now: t3,
    discovery: disc([page("/login", "observed", { sensitive_kind: "login" }), page("/", "error_status")]) });
  ok("page_reappeared event", evts(db, "ws_a").includes("/login:page_reappeared"));
  eq("error answer → unconfirmed, last_seen kept", [pageRow(db, "ws_a", "/").monitoring_status, pageRow(db, "ws_a", "/").last_seen_at], ["unconfirmed", t1]);
  ok("unconfirmed keeps last good observation", JSON.parse(pageRow(db, "ws_a", "/").last_observation_json)?.security_headers);
  // Re-running scan 3 is a no-op for events (deterministic ids).
  const before = evts(db, "ws_a").length;
  await persistWebsitePagesForScan(env, { workspace_id: "ws_a", domain_id: "d1", domain: "acme.test", scan_id: "s3", now: t3, discovery: disc([page("/login", "observed", { sensitive_kind: "login" }), page("/", "error_status")]) });
  eq("idempotent rerun: no duplicate events", evts(db, "ws_a").length, before);
  // Tenant isolation and eligibility.
  eq("unverified domain: nothing written", (await persistWebsitePagesForScan(env, { workspace_id: "ws_unv", domain_id: "d1", domain: "acme.test", scan_id: "s1", discovery: disc([page("/")]) })).skipped, "workspace_or_domain_not_eligible");
  db.prepare("UPDATE workspaces SET deleted_at = 'x' WHERE id = 'ws_b'").run();
  eq("deleted workspace: nothing written", (await persistWebsitePagesForScan(env, { workspace_id: "ws_b", domain_id: "d1", domain: "acme.test", scan_id: "s1", discovery: disc([page("/")]) })).skipped, "workspace_or_domain_not_eligible");
  eq("other workspaces have no rows", db.prepare("SELECT COUNT(*) AS n FROM website_pages WHERE workspace_id <> 'ws_a'").get().n, 0);
  eq("wrong module source ignored", (await persistWebsitePagesForScan(env, { workspace_id: "ws_a", domain_id: "d1", scan_id: "s9", discovery: { source: "headers" } })).skipped, "no_result");
  // Read surface.
  const listed = await listWebsitePages(env, "ws_a");
  eq("list: sensitive first", listed[0].pages.map((p) => p.path), ["/login", "/"]);
  eq("list: latest run", listed[0].latest_run?.scan_id, "s3");
  eq("list: other workspace sees nothing", (await listWebsitePages(env, "ws_b"))[0]?.pages?.length ?? 0, 0);
  // A page that stops carrying its sensitive signal is re-evaluated, not stuck.
  {
    const db2 = createDb(); const env2 = { cybermeters_db: d1(db2) };
    await persistWebsitePagesForScan(env2, { workspace_id: "ws_a", domain_id: "d1", domain: "acme.test", scan_id: "x1", discovery: disc([page("/portal", "observed", { sensitive_kind: "login", sensitive_basis: "password_field", password_field: true })]) });
    await persistWebsitePagesForScan(env2, { workspace_id: "ws_a", domain_id: "d1", domain: "acme.test", scan_id: "x2", discovery: disc([page("/portal")]) });
    eq("sensitive kind re-evaluated on each observation", pageRow(db2, "ws_a", "/portal").sensitive_kind, null);
  }
  eq("projection drops unknown fields", Object.keys(projectObservation(page("/x")).cookies[0]).sort(), ["httponly", "name", "samesite", "secure"]);
}
{
  // Route: auth, tenant scope, domain filter never widens.
  const db = createDb(); const env = { cybermeters_db: d1(db) };
  await persistWebsitePagesForScan(env, { workspace_id: "ws_a", domain_id: "d1", domain: "acme.test", scan_id: "s1", discovery: disc([page("/")]) });
  const call = async (wsId, { user = { id: "u" }, member = true, q = "", method = "GET" } = {}) => {
    const request = new Request(`https://api.example/api/workspaces/${wsId}/website-security/pages${q}`, { method });
    const r = await websiteSecurityRoutes({ request, env, url: new URL(request.url), json: (b, s = 200) => Response.json(b, { status: s }),
      requireAuth: async () => user, requireWorkspaceRole: async () => (member ? { role: "viewer" } : null) });
    return [r.status, await r.json()];
  };
  eq("route: unauthenticated 401", (await call("ws_a", { user: null }))[0], 401);
  eq("route: non-member 403", (await call("ws_a", { member: false }))[0], 403);
  eq("route: wrong method 405", (await call("ws_a", { method: "POST" }))[0], 405);
  const [st, body] = await call("ws_a");
  eq("route: member 200 with pages", [st, body.domains[0].pages.length], [200, 1]);
  ok("route: scope note says not a full crawl", /not a full crawl/.test(body.scope_note));
  eq("route: foreign domain filter → empty", (await call("ws_a", { q: "?domain=other.example" }))[1].domains, []);
  db.prepare("UPDATE workspaces SET deleted_at = 'x' WHERE id = 'ws_a'").run();
  eq("route: soft-deleted workspace 404", (await call("ws_a"))[0], 404);
}

// ── 5. Non-author review hardening ─────────────────────────────────────────
{
  // P1-1: hostile HTML is parsed in linear time (no catastrophic backtracking).
  const N = 98_304;
  const hostile = {
    links: "<a".repeat(N / 2), imgs: "<img".repeat(N / 4), forms: "<form".repeat(N / 5),
    inputs: "<input".repeat(N / 6), scripts: "<script".repeat(N / 7),
    farGt: "<a" + " x".repeat(N / 2) + ">", scriptsClosed: "<script>x</script>".repeat(N / 17),
    comments: "<!--".repeat(N / 4),
  };
  const time = (fn) => { const t = performance.now(); fn(); return performance.now() - t; };
  for (const [label, html] of Object.entries(hostile)) {
    const ms = Math.max(
      time(() => extractLinks(html)), time(() => findMixedContent(html, "https://acme.test/")),
      time(() => extractForms(html, "https://acme.test/", hosts)), time(() => hasPasswordField(html)),
      time(() => thirdPartyScriptHosts(html, "https://acme.test/", hosts)),
    );
    ok(`hostile HTML (${label}) parsed in linear time`, ms < 300, `${ms.toFixed(0)}ms`);
  }
  // Linear scaling: a 400 KB "<a<a…<a>" body (one far '>') must stay fast; a
  // scanner that re-searches for '>' per '<' is quadratic here (~0.5 s).
  {
    const big = "<a".repeat(200_000) + ">";
    let worst = 0;
    for (let k = 0; k < 3; k++) worst = Math.max(worst, time(() => extractLinks(big)));
    ok("scanner scales linearly on a 400 KB hostile body", worst < 150, `${worst.toFixed(0)}ms`);
  }
  // Whole module against a site serving hostile bodies on every page.
  const body = "<a href='/p1'>" + "<a".repeat(48_000);
  const routes = { "acme.test/": { body } };
  for (let i = 0; i < 20; i++) routes[`acme.test/p${i}`] = { body: `<a href='/p${i + 1}'>` + "<img".repeat(24_000) };
  const t0 = performance.now();
  await runPageDiscoveryModule("acme.test", { fetchImpl: site(routes) });
  ok("hostile site: whole module stays fast", performance.now() - t0 < 3_000, `${(performance.now() - t0).toFixed(0)}ms`);
}
{
  // Scanner semantics: comments and raw-text (script/style) content are not markup.
  eq("comment-hidden password field ignored", hasPasswordField("<!-- <input type=password> --><p>x</p>"), false);
  // nosemgrep: javascript.lang.security.audit.unknown-value-with-script-tag.unknown-value-with-script-tag -- INTENTIONAL: inert HTML fixture parsed (never rendered) by the scanner under test; `hosts` is a test-local Set.
  eq("script string '<form' ignored", extractForms(`<script>var s = "<form action='http://x'><input type=password>";</script>`, "https://acme.test/", hosts).length, 0);
  eq("mixed content inside script string ignored", findMixedContent(`<script>document.write('<img src="http://x/y.png">')</script>`, "https://acme.test/").count, 0);
  eq("data-href is not href", extractLinks(`<a data-href="/x">`), []);
  let seen = 0; forEachTag("<A HREF=/a><a\nhref='/b'>", new Set(["a"]), () => { seen++; });
  eq("tags across case and newlines", seen, 2);
}
{
  // P1-2: a long shared <head> does not make different pages "the same".
  const head = "<head>" + "<meta name=x content=y>".repeat(250) + "</head>"; // ~5.5 KB
  const r = await runPageDiscoveryModule("acme.test", { fetchImpl: site({
    "acme.test/": { body: `<html>${head}<body><a href="/login">in</a> home</body></html>` },
    "acme.test/login": { body: `<html>${head}<body><form method=post><input type=password></form></body></html>` },
  }) });
  eq("shared head: real page still observed", r.pages.find((p) => p.path === "/login")?.outcome, "observed");
}
{
  // DNS answering a private address: safeFetch refuses, nothing is fetched.
  const log = [];
  const privateDns = async (_host, type) => ({ Status: 0, Answer: type === "A" ? [{ name: "acme.test", type: 1, TTL: 60, data: "10.0.0.5" }] : [] });
  const r = await runPageDiscoveryModule("acme.test", { fetchImpl: site(baseRoutes, { log }), dnsResolver: privateDns });
  eq("private DNS: no request reaches the host", log.length, 0);
  eq("private DNS: not_run", r.coverage, "not_run");
  // And the scan engine wires the strict resolver into the module.
  const engineSrc = fs.readFileSync(path.join(root, "workers/scan-api/src/engines/scan-engine.js"), "utf8");
  ok("engine passes dnsResolver + dnsCache to page discovery",
    /runPageDiscoveryModule\(domain, \{\s*dnsResolver: dnsQuery, dnsCache, accounting, signal, remainingMs,\s*\}\)/.test(engineSrc));
}
{
  // robots.txt / sitemap-index entries off-host or on other ports are never fetched.
  const log = [];
  await runPageDiscoveryModule("acme.test", { fetchImpl: site({
    "acme.test/": { body: "<a href='/a'>" },
    "acme.test/robots.txt": { type: "text/plain", body: "Sitemap: https://acme.test:6379/s.xml\nSitemap: https://evil.example/s.xml\nSitemap: https://u:p@acme.test/s.xml\nSitemap: https://acme.test/index.xml" },
    "acme.test/index.xml": { type: "application/xml", body: "<sitemapindex><sitemap><loc>http://www.acme.test:22/x.xml</loc></sitemap><sitemap><loc>https://evil.example/y.xml</loc></sitemap></sitemapindex>" },
  }, { log }) });
  ok("sitemaps: no other host, port or credentials fetched",
    !log.some((u) => /:6379|:22\/|evil\.example|u:p@/.test(u)), JSON.stringify(log));
  // A robots.txt that redirects off-site is not parsed.
  const log2 = [];
  await runPageDiscoveryModule("acme.test", { fetchImpl: site({
    "acme.test/": { body: "<p>x</p>" },
    "acme.test/robots.txt": { redirect: "https://elsewhere.example/robots.txt" },
    "elsewhere.example/robots.txt": { type: "text/plain", body: "Sitemap: https://acme.test/secret-sitemap.xml" },
  }, { log: log2 }) });
  ok("off-site robots.txt is not parsed", !log2.some((u) => u.includes("secret-sitemap")), JSON.stringify(log2));
}
{
  // Privacy: redirect query strings and path session parameters never survive.
  const r = await runPageDiscoveryModule("acme.test", { fetchImpl: site({
    "acme.test/": { redirect: "https://acme.test/home?session=SECRET123#frag" },
    "acme.test/home": { body: "<a href='/login;jsessionid=JSESS42'>in</a>" },
    "acme.test/login": { body: "<form method=post><input type=password></form>" },
  }) });
  const dump = JSON.stringify(r);
  ok("no redirect query string or fragment kept", !/SECRET123|frag/.test(dump), dump.slice(0, 300));
  ok("no ;jsessionid kept", !dump.includes("JSESS42"));
  ok("session-parameter path normalised to the page", r.pages.some((p) => p.path === "/login" && p.outcome === "observed"));
}
{
  // Unicode domain: hosts are compared in their ASCII form.
  ok("unicode domain → punycode host", siteHosts("bücher.example").has("xn--bcher-kva.example"));
}
{
  // The module never carries a field the scan-quality / verification gates read.
  const FORBIDDEN = ["incomplete", "incomplete_reason", "skipped", "error", "degradations", "outcome"];
  const shapes = [
    await runPageDiscoveryModule("acme.test", { fetchImpl: site(baseRoutes) }),
    await runPageDiscoveryModule("acme.test", { fetchImpl: site(baseRoutes), remainingMs: () => 0 }),
    await runPageDiscoveryModule("acme.test", { fetchImpl: site({ "acme.test/": { status: 503 } }) }),
  ];
  ok("module result never carries scan-quality/verification fields", shapes.every((r) => FORBIDDEN.every((k) => !(k in r))));
  const engineSrc = fs.readFileSync(path.join(root, "workers/scan-api/src/engines/scan-engine.js"), "utf8");
  const notRunSrc = engineSrc.match(/const notRun = \(reason\) => \(\{([^\n]*)\}\);/)?.[1] || "";
  ok("engine notRun() carries no scan-quality/verification fields", notRunSrc && FORBIDDEN.every((k) => !new RegExp(`\\b${k}\\s*:`).test(notRunSrc)), notRunSrc);
  ok("engine leaves post-terminal headroom before launching", /deadline\.canRun\(PAGE_DISCOVERY_BUDGET_MS \+ PAGE_DISCOVERY_POST_TERMINAL_RESERVE_MS\)/.test(engineSrc));
}

{
  // Round-2 P1: catch-all site answering every unknown path with the homepage
  // shell plus a fresh CSRF token. Nothing that does not exist may be "observed".
  let n = 0;
  const shell = () => `<html><head>${"<meta name=x content=y>".repeat(250)}<meta name="csrf-token" content="${n++}-${Math.random()}"></head><body><a href="/about">About</a><form method=post action="/search"><input type=hidden name=csrf value="${Math.random()}"></form></body></html>`;
  const fetchImpl = async (url) => {
    const u = new URL(url);
    let res;
    if (u.pathname === "/real-login") res = new Response(`<html><body><form method=post action="/session"><input type=password name=pw></form></body></html>`, { headers: { "content-type": "text/html" } });
    else if (u.pathname === "/robots.txt" || u.pathname === "/sitemap.xml") res = new Response("nf", { status: 404 });
    else res = new Response(shell().replace("<body>", u.pathname === "/" ? `<body><a href="/real-login">in</a>` : "<body>"), { headers: { "content-type": "text/html" } });
    Object.defineProperty(res, "url", { value: url });
    return res;
  };
  const r = await runPageDiscoveryModule("acme.test", { fetchImpl });
  const observed = r.pages.filter((p) => p.outcome === "observed").map((p) => p.path).sort();
  eq("catch-all: only real pages are observed", observed, ["/", "/real-login"]);
  ok("catch-all: well-known probes are not recorded as seen", !r.pages.some((p) => ["/admin", "/account", "/checkout", "/login"].includes(p.path) && p.outcome === "observed"));
  eq("catch-all: /about (homepage shell) is a soft-404", r.pages.find((p) => p.path === "/about")?.outcome, "soft_404");
}
{
  // Round-2 P2(b): non-ASCII case folding must not shift raw-text skipping.
  const html = "İ".repeat(60) + "<title>x</title><style>a{}</style><script>var s='<a href=\"/fake\">';</script><a href=\"/hidden\">h</a>";
  eq("unicode before raw-text tags: real link found, script text ignored", extractLinks(html), ["/hidden"]);
  const html2 = "<title>" + "İ".repeat(8) + "</title><style>x</style><script>var s='<form action=\"https://collector.example/x\"><input type=password>'</script>";
  eq("unicode before raw-text tags: no invented form", extractForms(html2, "https://acme.test/", hosts).length, 0);
}

{
  // Round-2 P2(a): a workspace with more than 100 domains still lists (no 1+N binding).
  const db = createDb(); const env = { cybermeters_db: d1(db) };
  for (let i = 0; i < 150; i++) {
    db.prepare("INSERT INTO domains VALUES (?,?)").run(`dd${i}`, `d${i}.test`);
    db.prepare("INSERT INTO workspace_domains VALUES ('ws_a', ?, 'verified')").run(`dd${i}`);
  }
  let threw = null, listed = null;
  try { listed = await listWebsitePages(env, "ws_a"); } catch (e) { threw = e; }
  ok("150-domain workspace lists without error", !threw && Array.isArray(listed) && listed.length === 151, String(threw?.message || listed?.length));
  const listSrc = fs.readFileSync(path.join(root, "workers/scan-api/src/engines/website-pages.js"), "utf8");
  ok("list queries do not bind one parameter per domain", !/\.bind\(workspaceId, \.\.\.ids\)/.test(listSrc));
}

// ── 6. JavaScript path discovery (PR 15) ───────────────────────────────────
{
  const js = `const r=[{path:"/admin/panel"},{path:'/settings'}];fetch(\`/account/billing\`);go("/users/:id");x="\${y}/z";
    a="//cdn.example/lib.js";b="/static/js/main.js";c="/api/v1/users";d="/logout";e='/hidden-report';f="/img/logo";g="/a/../b"`;
  const found = extractJsPaths(js);
  eq("js paths: quoted literals extracted", found.filter((p) => ["/admin/panel", "/settings", "/account/billing", "/hidden-report", "/api/v1/users", "/logout"].includes(p)).sort(),
    ["/account/billing", "/admin/panel", "/api/v1/users", "/hidden-report", "/logout", "/settings"]);
  ok("js paths: parameterised, protocol-relative, asset and traversal paths excluded",
    !found.some((p) => p.includes(":") || p.startsWith("//") || p.startsWith("/static") || p.startsWith("/img") || p.includes("..")), JSON.stringify(found));
  eq("unsafe GETs are never requestable", ["/logout", "/account/delete", "/unsubscribe", "/sign-out", "/api/v1/users", "/graphql", "/wp-json/x", "/oauth/token"].map((p) => isRequestablePath(p)), [false, false, false, false, false, false, false, false]);
  eq("ordinary pages are requestable", ["/admin", "/account", "/pricing", "/reset-password", "/verify-email"].map((p) => isRequestablePath(p)), [true, true, true, true, true]);
  ok("api path classifier", isApiPath("/api/users") && !isApiPath("/apiary"));
  // nosemgrep: javascript.lang.security.audit.unknown-value-with-script-tag.unknown-value-with-script-tag -- INTENTIONAL: inert HTML fixture parsed (never rendered) by the scanner under test; `hosts` is a test-local Set.
  eq("first-party scripts only", firstPartyScriptUrls(`<script src="/a.js"></script><script src="https://cdn.other/x.js"></script><script src="https://www.acme.test/b.js"></script><script src="https://acme.test:8443/c.js"></script>`, "https://acme.test/", hosts),
    ["https://acme.test/a.js", "https://www.acme.test/b.js"]);
  // Linear on hostile JS.
  const hostileJs = "\"/".repeat(130_000) + "'" + "a".repeat(100_000);
  const t = performance.now(); extractJsPaths(hostileJs); const ms = performance.now() - t;
  ok("js path extraction is linear on hostile input", ms < 300, `${ms.toFixed(0)}ms`);
}
{
  const log = [];
  const r = await runPageDiscoveryModule("acme.test", { fetchImpl: site({
    "acme.test/": { body: `<a href="/logout">out</a><a href="/account/delete">del</a><script src="/app.js"></script><script src="https://cdn.vendor.example/v.js"></script>` },
    "acme.test/app.js": { type: "application/javascript", body: `routes=["/admin/panel","/hidden-report","/api/users","/logout","/users/:id"]` },
    "acme.test/admin/panel": { body: "<form method=post><input type=password></form>" },
    "acme.test/hidden-report": { body: "<html>report</html>" },
  }, { log }) });
  const by = Object.fromEntries(r.pages.map((p) => [p.path, p]));
  eq("js: admin path from JavaScript observed", [by["/admin/panel"]?.source, by["/admin/panel"]?.outcome, by["/admin/panel"]?.sensitive_kind], ["javascript", "observed", "login"]);
  eq("js: hidden page from JavaScript observed", [by["/hidden-report"]?.source, by["/hidden-report"]?.outcome], ["javascript", "observed"]);
  ok("js: logout and delete are never requested", !log.some((u) => /\/logout|\/account\/delete/.test(u)), JSON.stringify(log));
  ok("js: API endpoints are never requested", !log.some((u) => u.includes("/api/")));
  ok("js: third-party script not fetched", !log.some((u) => u.includes("cdn.vendor.example")));
  eq("js: counts", [r.javascript.scripts_read, r.javascript.api_paths_found, r.javascript.paths_seen], [1, 1, 2]);
  ok("js: unsafe paths counted as skipped", r.sources.unsafe_skipped >= 2);
  // Persisted with its source.
  const db = createDb(); const env = { cybermeters_db: d1(db) };
  await persistWebsitePagesForScan(env, { workspace_id: "ws_a", domain_id: "d1", domain: "acme.test", scan_id: "js1", discovery: r });
  eq("js: source persisted", pageRow(db, "ws_a", "/hidden-report")?.discovery_source, "javascript");
  const counts = JSON.parse(db.prepare("SELECT counts_json FROM website_page_discovery_runs WHERE scan_id='js1'").get().counts_json);
  eq("js: run counts persisted", [counts.js_scripts_read, counts.js_api_paths_found, counts.js_paths_seen], [1, 1, 2]);
}

// ── 7. Round-3 review hardening ────────────────────────────────────────────
async function catchAllRun({ echo, realPages = {} }) {
  let n = 0;
  const layout = (path, title, body) => `<html><head><title>${title}</title>${"<meta name=x content=y>".repeat(220)}<meta name="csrf-token" content="${n++}">${echo(path)}</head><body><nav><a href="/">Home</a><a href="/about">About</a></nav>${body}</body></html>`;
  const fetchImpl = async (url) => {
    const u = new URL(url);
    let res;
    if (u.pathname === "/robots.txt" || u.pathname === "/sitemap.xml") res = new Response("nf", { status: 404 });
    else if (u.pathname === "/") res = new Response(layout("/", "Acme", `<a href="/contact">Contact</a><a href="/about">x</a>`), { headers: { "content-type": "text/html" } });
    else if (realPages[u.pathname]) res = new Response(layout(u.pathname, realPages[u.pathname].title, realPages[u.pathname].body || ""), { headers: { "content-type": "text/html" } });
    else res = new Response(layout(u.pathname, `${u.pathname.slice(1).replace(/-/g, " ")} | Acme`, "<p>Sorry</p>"), { headers: { "content-type": "text/html" } });
    Object.defineProperty(res, "url", { value: url });
    return res;
  };
  return runPageDiscoveryModule("acme.test", { fetchImpl });
}
{
  const echoes = {
    canonical: (p) => `<link rel="canonical" href="https://acme.test${p}">`,
    hreflang: (p) => `<link rel="alternate" hreflang="de" href="/de${p}">`,
    breadcrumb: (p) => `<a class="crumb" href="${p}">here</a>`,
    title_and_link: (p) => `<a href="https://acme.test${p}">${p.slice(1)}</a>`,
  };
  for (const [label, echo] of Object.entries(echoes)) {
    const r = await catchAllRun({ echo });
    const observed = r.pages.filter((p) => p.outcome === "observed").map((p) => p.path).sort();
    eq(`catch-all echoing path (${label}): nothing fake observed`, observed, ["/"]);
  }
  // Real pages on a catch-all site with the same layout but their own titles stay observed.
  const r = await catchAllRun({ echo: (p) => `<link rel="canonical" href="https://acme.test${p}">`,
    realPages: { "/about": { title: "About us — our story" }, "/contact": { title: "Contact the team", body: "<form method=post action='/send'><input name=email></form>" } } });
  eq("catch-all: real pages with their own titles still observed", r.pages.filter((p) => p.outcome === "observed").map((p) => p.path).sort(), ["/", "/about", "/contact"]);
}
{
  // Baseline probe unavailable → coverage says it could not tell.
  const fetchImpl = async (url) => {
    const u = new URL(url);
    let res;
    if (u.pathname.startsWith("/cybermeters-check-")) res = new Response("boom", { status: 503, headers: { "content-type": "text/html" } });
    else if (u.pathname === "/") res = new Response("<a href='/a'>a</a>", { headers: { "content-type": "text/html" } });
    else res = new Response("nf", { status: 404 });
    Object.defineProperty(res, "url", { value: url });
    return res;
  };
  const r = await runPageDiscoveryModule("acme.test", { fetchImpl });
  ok("baseline unavailable recorded as a partial reason", r.partial_reasons.includes("catch_all_baseline_unavailable"), JSON.stringify(r.partial_reasons));
}
{
  const unsafe = ["/sign_out", "/log_out", "/signoff", "/doLogout", "/logoutUser", "/user/logoutAll", "/account/close", "/sessions/end",
    "/exit", "/opt-out", "/optout", "/cart/clear", "/cart/add/123", "/add-to-cart", "/admin/cache/clear", "/admin/cache/flush",
    "/admin/reindex", "/jobs/run", "/cron", "/install", "/admin/users/123/ban", "/subscription/suspend", "/account%2Flogout"];
  const allowed = unsafe.filter((p) => isRequestablePath(p));
  eq("word classifier: every reviewer unsafe example refused", allowed, []);
  eq("word classifier: sensitive pages stay requestable", ["/reset-password", "/password/reset", "/account/reset-pin", "/verify-email", "/login", "/my-account"].filter((p) => !isRequestablePath(p)), []);
  eq("strict (JavaScript) mode refuses action verbs", ["/products/new", "/report/export", "/settings/update"].filter((p) => isRequestablePath(p, { strict: true })), []);
  ok("strict mode still allows sensitive pages", isRequestablePath("/admin/users", { strict: true }) && isRequestablePath("/account/billing", { strict: true }));
  eq("api classifier extended", ["/v1/users", "/v2", "/trpc/user.get", "/jsonrpc", "/odata/Products", "/services/data", "/socket.io/", "/livewire/message", "/wp-admin/admin-ajax.php"].filter((p) => !isApiPath(p)), []);
  eq("pathWords splits camelCase and %-encoding", pathWords("/user/logoutAll/a%2Fb-c_d"), ["user", "logout", "all", "a", "b", "c", "d"]);
}
{
  // JS counts are unique; JS paths that are not real pages are counted, not listed.
  const r = await runPageDiscoveryModule("acme.test", { fetchImpl: site({
    "acme.test/": { body: `<script src="/a.js"></script><script src="/b.js"></script>` },
    "acme.test/a.js": { type: "application/javascript", body: `x=["/hidden-report","/promo-x"]` },
    "acme.test/b.js": { type: "application/javascript", body: `y=["/hidden-report"]` },
    "acme.test/hidden-report": { body: "<html>r</html>" },
    "acme.test/promo-x": { redirect: "https://acme.test/" },
  }) });
  eq("js: unique paths counted once", r.javascript.paths_found, 2);
  eq("js: checked vs seen", [r.javascript.paths_checked, r.javascript.paths_seen], [2, 1]);
  ok("js: soft-404 JS path not listed in pages", !r.pages.some((p) => p.path === "/promo-x"));
}

// ── 4. End-to-end engine trace: queue scan → module → D1 inventory ─────────
{
  const NOW = "2026-10-11T09:00:00.000Z";
  const NOW_MS = Date.parse(NOW);
  const buildDb = () => {
    const db = new DatabaseSync(":memory:");
    // schema.sql already contains most migrations: only that overlap is tolerated.
    const apply = (f) => { try { db.exec(fs.readFileSync(f, "utf8")); } catch (e) { if (!/^(?:duplicate column name|no such table|table \S+ already exists|index \S+ already exists)/.test(e.message)) throw e; } };
    apply(path.join(root, "database/schema.sql"));
    for (const f of fs.readdirSync(path.join(root, "database/migrations")).filter((n) => n.endsWith(".sql")).sort()) apply(path.join(root, "database/migrations", f));
    db.exec("PRAGMA foreign_keys = OFF");
    return db;
  };
  const makeD1 = (db) => {
    const stmt = (sql, args = []) => ({
      __sql: sql, bind: (...b) => stmt(sql, b),
      first: async (col) => { const r = db.prepare(sql).get(...args) ?? null; return col && r ? r[col] : r; },
      all: async () => ({ results: db.prepare(sql).all(...args), success: true, meta: {} }),
      run: async () => { const r = db.prepare(sql).run(...args); return { success: true, meta: { changes: r.changes, last_row_id: Number(r.lastInsertRowid || 0) } }; },
    });
    return { prepare: (sql) => stmt(sql), exec: async (sql) => { db.exec(sql); return {}; },
      batch: async (list) => { const out = []; db.exec("BEGIN"); try { for (const x of list) out.push(/^\s*select/i.test(x.__sql) ? await x.all() : await x.run()); db.exec("COMMIT"); return out; } catch (e) { db.exec("ROLLBACK"); throw e; } } };
  };
  const makeR2 = (store) => ({ get: async (k) => { const b = store.get(String(k)); return b == null ? null : { text: async () => b, json: async () => JSON.parse(b) }; },
    put: async (k, b) => { store.set(String(k), String(b)); return {}; }, delete: async () => ({}), head: async () => null, list: async () => ({ objects: [] }) });
  const j = (b, st = 200) => new Response(JSON.stringify(b), { status: st, headers: { "content-type": "application/json" } });
  const pageRequests = [];
  const install = () => {
    globalThis.fetch = async (input) => {
      const url = new URL(String(input));
      const host = url.hostname;
      if (host === "crt.sh") return j([]);
      if (host === "api.certspotter.com") return j([]);
      if (host === "cloudflare-dns.com" || host === "dns.google") {
        const name = String(url.searchParams.get("name") || "").toLowerCase();
        const type = String(url.searchParams.get("type") || "A").toUpperCase();
        if ((name === "example.com" || name === "www.example.com") && type === "A") return j({ Status: 0, Answer: [{ type: 1, data: "93.184.216.34" }] });
        return j({ Status: 0, Answer: [] });
      }
      if (url.protocol === "http:" && (host === "example.com" || host === "www.example.com")) return new Response("", { status: 301, headers: { location: `https://${host}${url.pathname}` } });
      if (url.protocol === "https:" && host === "example.com") {
        pageRequests.push(url.pathname);
        if (url.pathname === "/") return new Response(`<html><a href="/login">Sign in</a><a href="/about">About</a></html>`, { status: 200, headers: { "content-type": "text/html", "strict-transport-security": "max-age=31536000" } });
        if (url.pathname === "/login") { const h = new Headers({ "content-type": "text/html" }); h.append("set-cookie", "session=TRACEVALUE; Path=/"); return new Response(`<form method=post action="https://collector.example/x"><input type=password></form>`, { status: 200, headers: h }); }
        if (url.pathname === "/about") return new Response(`<html>About us</html>`, { status: 200, headers: { "content-type": "text/html" } });
        return new Response("nf", { status: 404, headers: { "content-type": "text/html" } });
      }
      return new Response("<html></html>", { status: 200, headers: { "content-type": "text/html" } });
    };
  };
  const run = async (executionContext) => {
    const db = buildDb(); const store = new Map();
    const env = { cybermeters_db: makeD1(db), cybermeters_reports: makeR2(store), SCAN_CAPACITY_MODE: "legacy", SCAN_SUBREQUEST_LIMIT: "200", SCAN_DEADLINE_MS: "115000", APP_VERSION: "page-trace" };
    db.prepare("INSERT INTO users (id, email) VALUES ('usr','owner@example.com')").run();
    db.prepare("INSERT INTO workspaces (id, name, deleted_at) VALUES ('ws','Trace',NULL)").run();
    db.prepare("INSERT INTO domains (id, user_id, domain) VALUES ('dom','usr','example.com')").run();
    db.prepare("INSERT INTO workspace_domains (workspace_id, domain_id, verification_status) VALUES ('ws','dom','verified')").run();
    db.prepare(`INSERT INTO scans (id, workspace_id, domain_id, domain, status, scan_quality, created_at) VALUES ('scan-pd','ws','dom','example.com','running',NULL,?)`).run(NOW);
    const prevFetch = globalThis.fetch, prevErr = console.error, prevWarn = console.warn, prevLog = console.log;
    install(); console.error = () => {}; console.warn = () => {}; console.log = () => {};
    try { await runScanEngine("scan-pd", "dom", "ws", "example.com", env, { now: () => NOW_MS, executionContext, trigger: "manual" }); }
    finally { globalThis.fetch = prevFetch; console.error = prevErr; console.warn = prevWarn; console.log = prevLog; }
    const raw = store.get("reports/scan-pd.json");
    return { db, report: raw ? JSON.parse(raw) : null };
  };
  const { db, report } = await run("queue");
  const mod = report?.modules?.page_discovery;
  ok("trace: queue scan produced a page_discovery module", mod?.source === "page_discovery", JSON.stringify(mod)?.slice(0, 200));
  ok("trace: module never marks the scan incomplete", mod && !("incomplete" in mod));
  const login = mod?.pages?.find((p) => p.path === "/login");
  eq("trace: login page observed with off-site password form", [login?.outcome, login?.sensitive_kind, login?.forms?.[0]?.action_kind], ["observed", "login", "other_origin"]);
  const row = db.prepare("SELECT sensitive_kind, monitoring_status, last_observation_json FROM website_pages WHERE workspace_id='ws' AND path='/login'").get();
  eq("trace: inventory row persisted for the verified workspace", [row?.sensitive_kind, row?.monitoring_status], ["login", "observed"]);
  ok("trace: no cookie value persisted or reported", !String(row?.last_observation_json).includes("TRACEVALUE") && !JSON.stringify(mod).includes("TRACEVALUE"));
  eq("trace: run row persisted", db.prepare("SELECT COUNT(*) AS n FROM website_page_discovery_runs WHERE scan_id='scan-pd'").get().n, 1);
  ok("trace: scan completed", ["completed"].includes(db.prepare("SELECT status FROM scans WHERE id='scan-pd'").get()?.status));
  const q = await run("waituntil");
  eq("trace: non-durable scan does not crawl", [q.report?.modules?.page_discovery?.coverage, q.report?.modules?.page_discovery?.partial_reasons?.[0]], ["not_run", "not_durable_execution"]);
  eq("trace: non-durable scan writes no pages", q.db.prepare("SELECT COUNT(*) AS n FROM website_pages").get().n, 0);
  const qMod = q.report?.modules?.page_discovery || {};
  ok("trace: not_run module carries no scan-quality/verification fields",
    ["incomplete", "incomplete_reason", "skipped", "error", "degradations", "outcome"].every((k) => !(k in qMod)), JSON.stringify(qMod));
}

console.log(`validate-website-page-discovery: ${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
