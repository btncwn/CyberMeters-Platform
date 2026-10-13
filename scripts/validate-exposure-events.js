#!/usr/bin/env node
//
// Exposure-timeline regression: asset inventory emits DNS-level change events
// when an existing asset's IP, CNAME or redirect target changes between scans.
// Also: only the scanning workspace's inventory is written, each row keeps the
// first and last time every source named it, and a redirect location is kept
// without its query, fragment or path parameters.
// Drives upsertAssetInventory against a real in-memory SQLite schema
// (schema.sql + migrations) via the same D1 adapter pattern used by the
// request-pipeline harness. Requires Node 24+ (node:sqlite). CI-blocking.
//
import fs from "node:fs";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const { upsertAssetInventory } = await import(pathToFileURL(path.join(root, "workers", "scan-api", "src", "engines", "asset-inventory.js")).href);
const { buildAssetTimelineTrustMetadata } = await import(pathToFileURL(path.join(root, "workers", "scan-api", "src", "engines", "timeline-trust.js")).href);

let pass = 0, fail = 0;
const ok = (name, cond) => { cond ? pass++ : fail++; if (!cond) console.log("FAIL " + name); };

function buildDb() {
  const db = new DatabaseSync(":memory:");
  const apply = (p) => { try { db.exec(fs.readFileSync(p, "utf8")); } catch { /* ordering/dup — schema still converges */ } };
  apply(path.join(root, "database", "schema.sql"));
  for (const f of fs.readdirSync(path.join(root, "database", "migrations")).filter((f) => f.endsWith(".sql")).sort()) {
    apply(path.join(root, "database", "migrations", f));
  }
  db.exec("PRAGMA foreign_keys = OFF");
  return db;
}

function makeD1(db) {
  const wrap = (sql, args) => ({
    __sql: sql, __args: args,
    first: async (col) => { const r = db.prepare(sql).get(...args) ?? null; return col && r ? r[col] : r; },
    all:   async () => ({ results: db.prepare(sql).all(...args), success: true, meta: {} }),
    run:   async () => { const r = db.prepare(sql).run(...args); return { success: true, meta: { changes: r.changes, last_row_id: Number(r.lastInsertRowid ?? 0) } }; },
  });
  return {
    prepare(sql) { const b = wrap(sql, []); b.bind = (...args) => wrap(sql, args); return b; },
    async batch(stmts) { return Promise.all(stmts.map((s) => (/^\s*select/i.test(s.__sql) ? s.all() : s.run()))); },
    async exec(sql) { db.exec(sql); return { count: 0, duration: 0 }; },
  };
}

function report() {
  return {
    scan_quality: { status: "complete" },
    timeline_trust: buildAssetTimelineTrustMetadata(),
    modules: {},
  };
}

function makeR2() {
  return {
    async get(key) {
      if (key !== "reports/scan_prev.json") return null;
      return { json: async () => report() };
    },
  };
}

function harness() {
  const db = buildDb();
  const env = { cybermeters_db: makeD1(db), cybermeters_reports: makeR2() };
  db.prepare("INSERT INTO users (id, email) VALUES (?, ?)").run("usr_1", "owner@example.co.uk");
  db.prepare("INSERT INTO domains (id, user_id, domain) VALUES (?, ?, ?)").run("dom_1", "usr_1", "example.co.uk");
  db.prepare("INSERT INTO workspaces (id, name) VALUES (?, ?)").run("ws_1", "Acme");
  db.prepare("INSERT INTO workspace_domains (workspace_id, domain_id) VALUES (?, ?)").run("ws_1", "dom_1");
  db.prepare("INSERT INTO scans (id, domain_id, domain, status, scan_quality, workspace_id, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)").run("scan_prev", "dom_1", "example.co.uk", "completed", "complete", "ws_1", "2026-07-17T10:00:00.000Z");
  db.prepare("INSERT INTO scans (id, domain_id, domain, status, scan_quality, workspace_id, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)").run("scan_1", "dom_1", "example.co.uk", "completed", "complete", "ws_1", "2026-07-18T10:00:00.000Z");
  return { db, env };
}

function seedAsset(db, { hostname = "www.example.co.uk", ip_addresses = null, cname = null, redirect_to = null } = {}) {
  db.prepare(
    `INSERT INTO workspace_assets
       (id, workspace_id, domain_id, hostname, asset_type, source,
        first_seen, last_seen, status, wildcard_dns,
        ip_addresses, cname, redirect_to, created_at, updated_at)
     VALUES (?, 'ws_1', 'dom_1', ?, 'subdomain', 'dns_bruteforce',
             datetime('now','-1 day'), datetime('now','-1 day'), 'active', 0,
             ?, ?, ?, datetime('now','-1 day'), datetime('now','-1 day'))`
  ).run(`asset_${hostname.replace(/[^a-z0-9]+/gi, "_")}`, hostname, ip_addresses, cname, redirect_to);
}

async function runInventory(env, modules, opts = {}) {
  return upsertAssetInventory(opts.scanId ?? "scan_1", "dom_1", "example.co.uk", {
    subdomains: { items: [], wildcard_dns: false },
    dns_bruteforce: { items: [] },
    asset_exposure: { assets: [] },
    ...modules,
  }, env, { currentReport: report(), workspaceId: "ws_1", ...opts });
}

const rows = (db, eventType) => db.prepare("SELECT event_type, hostname, severity, description FROM asset_events WHERE event_type = ? ORDER BY created_at").all(eventType);

// 1. Existing asset IP changes: exactly one event with old -> new description.
{
  const { db, env } = harness();
  seedAsset(db, { ip_addresses: JSON.stringify(["1.1.1.1"]) });
  await runInventory(env, {
    dns_bruteforce: { items: [{ hostname: "www.example.co.uk", ip_addresses: ["2.2.2.2"] }] },
  });
  const events = rows(db, "dns_ip_changed");
  ok("IP change emits exactly one dns_ip_changed event", events.length === 1);
  ok("IP change description contains old and new values", events[0]?.description === "IP address for www.example.co.uk changed: 1.1.1.1 → 2.2.2.2");
}

// 2. redirect_to null -> value is first-seen enrichment, not a change event.
{
  const { db, env } = harness();
  seedAsset(db, { hostname: "app.example.co.uk", cname: "old.vendor.example" });
  await runInventory(env, {
    asset_exposure: { assets: [{ host: "app.example.co.uk", cname: "new.vendor.example" }] },
  });
  const events = rows(db, "dns_cname_changed");
  ok("CNAME change emits exactly one dns_cname_changed event", events.length === 1);
  ok("CNAME change description contains old and new values", events[0]?.description === "CNAME for app.example.co.uk changed: old.vendor.example → new.vendor.example");
}

// 3. redirect_to null -> value is first-seen enrichment, not a change event.
{
  const { db, env } = harness();
  seedAsset(db, { hostname: "app.example.co.uk", redirect_to: null });
  await runInventory(env, {
    asset_exposure: { assets: [{ host: "app.example.co.uk", redirect_to: "https://external.example.net/path" }] },
  });
  ok("redirect null -> value does not emit dns_redirect_changed", rows(db, "dns_redirect_changed").length === 0);
}

// 4. redirect_to A -> external B emits high-severity redirect change.
{
  const { db, env } = harness();
  seedAsset(db, { hostname: "app.example.co.uk", redirect_to: "https://old.example.co.uk/start" });
  await runInventory(env, {
    asset_exposure: { assets: [{ host: "app.example.co.uk", redirect_to: "https://external.example.net/path" }] },
  });
  const events = rows(db, "dns_redirect_changed");
  ok("external redirect change emits one dns_redirect_changed event", events.length === 1);
  ok("external redirect change severity is high", events[0]?.severity === "high");
  ok("redirect description contains old and new values", events[0]?.description === "app.example.co.uk now redirects to https://external.example.net/path (was https://old.example.co.uk/start)");
}

// 5. Same IP on the next scan does not emit a change event.
{
  const { db, env } = harness();
  seedAsset(db, { ip_addresses: JSON.stringify(["1.1.1.1"]) });
  await runInventory(env, {
    dns_bruteforce: { items: [{ hostname: "www.example.co.uk", ip_addresses: ["1.1.1.1"] }] },
  });
  ok("same IP emits no dns_ip_changed event", rows(db, "dns_ip_changed").length === 0);
}

// 6. Dedupe: a second IP change event for the same hostname within 24h is suppressed.
{
  const { db, env } = harness();
  seedAsset(db, { ip_addresses: JSON.stringify(["1.1.1.1"]) });
  await runInventory(env, {
    dns_bruteforce: { items: [{ hostname: "www.example.co.uk", ip_addresses: ["2.2.2.2"] }] },
  });
  await runInventory(env, {
    dns_bruteforce: { items: [{ hostname: "www.example.co.uk", ip_addresses: ["3.3.3.3"] }] },
  });
  ok("second IP change within 24h is deduped", rows(db, "dns_ip_changed").length === 1);
}

// 7. Configuration references (SRV targets, hosts the home page links to)
//    persist only once DNS answered for them, with their own source; a
//    reference DNS never confirmed is not an asset; a name another source
//    already found keeps the most specific source; a third party is never added.
{
  const { db, env } = harness();
  await runInventory(env, {
    subdomains: {
      items: ["portal.example.co.uk", "vpn.example.co.uk"],
      wildcard_dns: false,
      referenced_hostnames: {
        confirmed: [
          { hostname: "autodiscover.example.co.uk", asset_source: "dns_srv", ip_addresses: ["192.0.2.10"] },
          { hostname: "status.example.co.uk", asset_source: "html_link", ip_addresses: ["192.0.2.11"] },
          { hostname: "portal.example.co.uk", asset_source: "dns_srv", ip_addresses: ["192.0.2.12"] },
        ],
      },
    },
    dns_bruteforce: {
      items: [],
      srv_items: [
        { hostname: "stale-target.example.co.uk", source: "dns_srv", record: "_sip._tls.example.co.uk" },
      ],
    },
    technology_detection: { linked_hostnames: ["old-link.example.co.uk", "partner.example.org"] },
  });
  const sourceOf = (hostname) => db.prepare("SELECT source FROM workspace_assets WHERE workspace_id = 'ws_1' AND hostname = ?").get(hostname)?.source ?? null;
  ok("SRV target confirmed by DNS persists as dns_srv", sourceOf("autodiscover.example.co.uk") === "dns_srv");
  ok("home-page link confirmed by DNS persists as html_link", sourceOf("status.example.co.uk") === "html_link");
  ok("an SRV target or link DNS never confirmed is not an asset",
    sourceOf("stale-target.example.co.uk") === null && sourceOf("old-link.example.co.uk") === null);
  ok("a link to another organisation's domain is never an asset", sourceOf("partner.example.org") === null);
  ok("a name several sources found keeps the most specific source", sourceOf("portal.example.co.uk") === "dns_srv");
  ok("a name only the merged discovery set carries persists as dns_discovery", sourceOf("vpn.example.co.uk") === "dns_discovery");
  ok("each referenced host is stored once",
    db.prepare("SELECT COUNT(*) AS n FROM workspace_assets WHERE workspace_id = 'ws_1' AND hostname = 'portal.example.co.uk'").get().n === 1);
}

// A probe is a check, not a sighting. A re-checked name the probe did not
// observe keeps its last_seen; a name the probe observed (an address, an
// existing DNS name, an HTTP response) refreshes it.
{
  const { db, env } = harness();
  seedAsset(db, { hostname: "gone.example.co.uk" });
  seedAsset(db, { hostname: "mail.example.co.uk" });
  const lastSeen = (hostname) => db.prepare("SELECT last_seen FROM workspace_assets WHERE workspace_id = 'ws_1' AND hostname = ?").get(hostname)?.last_seen ?? null;
  const before = { gone: lastSeen("gone.example.co.uk"), mail: lastSeen("mail.example.co.uk") };
  await runInventory(env, {
    asset_exposure: {
      assets: [
        { host: "gone.example.co.uk", reachable: false, status: null, probe_status: "not_applicable" },
        { host: "mail.example.co.uk", reachable: false, status: null, probe_status: "not_applicable" },
      ],
      removal_observations: [
        { host: "gone.example.co.uk", signal_states: { dns_resolution: { state: "absent" }, http_https_service: { state: "not_observed" } } },
        { host: "mail.example.co.uk", signal_states: { dns_resolution: { state: "observed", reason: "dns_name_without_address" }, http_https_service: { state: "not_observed" } } },
      ],
    },
  });
  ok("a re-checked name the probe did not observe keeps its last_seen", lastSeen("gone.example.co.uk") === before.gone);
  ok("a re-checked name that still exists in DNS refreshes last_seen", lastSeen("mail.example.co.uk") !== before.mail);
}
{
  const { db, env } = harness();
  seedAsset(db, { hostname: "legacy.example.co.uk" });
  const lastSeen = () => db.prepare("SELECT last_seen FROM workspace_assets WHERE workspace_id = 'ws_1' AND hostname = 'legacy.example.co.uk'").get()?.last_seen ?? null;
  const before = lastSeen();
  await runInventory(env, { asset_exposure: { assets: [{ host: "legacy.example.co.uk", reachable: false, status: null }] } });
  ok("without removal observations an unanswered probe is not a sighting", lastSeen() === before);
  await runInventory(env, { asset_exposure: { assets: [{ host: "legacy.example.co.uk", reachable: true, status: 200 }] } });
  ok("without removal observations an HTTP response is a sighting", lastSeen() !== before);
}

// 8. Only the scanning workspace is written. Another workspace linked to the
//    same domain keeps its own inventory; nothing is written without one.
{
  const { db, env } = harness();
  db.prepare("INSERT INTO workspaces (id, name) VALUES (?, ?)").run("ws_2", "Other");
  db.prepare("INSERT INTO workspace_domains (workspace_id, domain_id) VALUES (?, ?)").run("ws_2", "dom_1");
  const result = await runInventory(env, {
    subdomains: {
      items: ["private.example.co.uk"],
      wildcard_dns: false,
      customer_hostnames: { confirmed: [{ hostname: "private.example.co.uk", source: "customer_list", ip_addresses: ["192.0.2.20"] }] },
    },
  });
  const count = (workspace) => db.prepare("SELECT COUNT(*) AS n FROM workspace_assets WHERE workspace_id = ?").get(workspace).n;
  ok("the scanning workspace's inventory is written", result?.written === true && count("ws_1") === 2);
  ok("a name one workspace listed never reaches another workspace on the same domain", count("ws_2") === 0);
  const unbound = await upsertAssetInventory("scan_1", "dom_1", "example.co.uk", {
    subdomains: { items: ["another.example.co.uk"], wildcard_dns: false }, dns_bruteforce: { items: [] }, asset_exposure: { assets: [] },
  }, env, { currentReport: report() });
  ok("without a workspace nothing is written", unbound?.written === false && unbound?.reason === "no_workspace" &&
    db.prepare("SELECT COUNT(*) AS n FROM workspace_assets WHERE hostname = 'another.example.co.uk'").get().n === 0);
  db.prepare("UPDATE workspaces SET deleted_at = datetime('now') WHERE id = 'ws_1'").run();
  const deleted = await runInventory(env, { subdomains: { items: ["late.example.co.uk"], wildcard_dns: false } });
  ok("a deleted workspace is not written", deleted?.written === false &&
    db.prepare("SELECT COUNT(*) AS n FROM workspace_assets WHERE hostname = 'late.example.co.uk'").get().n === 0);
}

// 9. Each row keeps where it was seen, per source: first and last time.
{
  const { db, env } = harness();
  const sightings = (hostname) => JSON.parse(db.prepare("SELECT sightings_json FROM workspace_assets WHERE workspace_id = 'ws_1' AND hostname = ?").get(hostname)?.sightings_json ?? "null");
  const seen = {
    subdomains: {
      items: ["app.example.co.uk"],
      wildcard_dns: false,
      referenced_hostnames: { confirmed: [{ hostname: "app.example.co.uk", asset_source: "tls_certificate_name", sources: ["live_tls_san", "csp"], ip_addresses: ["192.0.2.30"] }] },
    },
    dns_bruteforce: { items: [{ hostname: "app.example.co.uk", ip_addresses: ["192.0.2.30"] }] },
  };
  await runInventory(env, seen, { observedAt: "2026-07-18T10:00:00.000Z" });
  const first = sightings("app.example.co.uk");
  ok("a new name records every source that named it",
    JSON.stringify(Object.keys(first?.sources || {}).sort()) === JSON.stringify(["csp_reference", "dns_bruteforce", "tls_certificate_name"]));
  ok("a new name's record starts with the scan that found it",
    first?.recorded_since === "2026-07-18T10:00:00.000Z" && first?.sources?.dns_bruteforce?.first_scan_id === "scan_1");
  await runInventory(env, { dns_bruteforce: { items: [{ hostname: "app.example.co.uk", ip_addresses: ["192.0.2.30"] }] } },
    { observedAt: "2026-07-19T10:00:00.000Z", scanId: "scan_2" });
  const second = sightings("app.example.co.uk");
  ok("a later scan moves only the sources that named the name again",
    second?.sources?.dns_bruteforce?.first_seen_at === "2026-07-18T10:00:00.000Z" &&
      second?.sources?.dns_bruteforce?.last_seen_at === "2026-07-19T10:00:00.000Z" &&
      second?.sources?.dns_bruteforce?.last_scan_id === "scan_2" &&
      second?.sources?.tls_certificate_name?.last_seen_at === "2026-07-18T10:00:00.000Z");
  await runInventory(env, seen, { observedAt: "2026-07-18T10:00:00.000Z" });
  ok("replaying an older scan never moves a sighting backwards",
    sightings("app.example.co.uk")?.sources?.dns_bruteforce?.last_seen_at === "2026-07-19T10:00:00.000Z");
  seedAsset(db, { hostname: "legacy.example.co.uk" });
  await runInventory(env, { asset_exposure: { assets: [{ host: "legacy.example.co.uk", reachable: true, status: 200 }] } },
    { observedAt: "2026-07-20T10:00:00.000Z", scanId: "scan_3" });
  ok("a row recorded before sightings gets none invented when no source names it", sightings("legacy.example.co.uk") === null);
  await runInventory(env, { dns_bruteforce: { items: [{ hostname: "legacy.example.co.uk", ip_addresses: ["192.0.2.31"] }] } },
    { observedAt: "2026-07-21T10:00:00.000Z", scanId: "scan_4" });
  const legacy = sightings("legacy.example.co.uk");
  ok("its record starts the first time a source names it, and says so",
    legacy?.recorded_since === "2026-07-21T10:00:00.000Z" && Object.keys(legacy?.sources || {}).join() === "dns_bruteforce");
}

// 10. A redirect location is kept without its query, fragment or path
//     parameters; an old row stored with them is compared without them.
{
  const { db, env } = harness();
  seedAsset(db, { hostname: "login.example.co.uk", redirect_to: "https://idp.example.co.uk/authorize?state=OLDSECRET#x" });
  await runInventory(env, {
    asset_exposure: { assets: [{ host: "login.example.co.uk", redirect_to: "https://idp.example.co.uk/authorize;jsessionid=ABC?state=NEWSECRET&code=123#frag" }] },
  });
  const stored = db.prepare("SELECT redirect_to FROM workspace_assets WHERE workspace_id = 'ws_1' AND hostname = 'login.example.co.uk'").get().redirect_to;
  ok("the stored redirect keeps scheme, host and path only", stored === "https://idp.example.co.uk/authorize");
  ok("a query that changed is not a redirect change", rows(db, "dns_redirect_changed").length === 0);
  ok("no secret reaches the inventory or its events",
    !/SECRET|code=|jsessionid/.test(JSON.stringify(db.prepare("SELECT * FROM workspace_assets").all()) + JSON.stringify(db.prepare("SELECT * FROM asset_events").all())));
}

console.log(`\nExposure events: ${pass}/${pass + fail} passed`);
if (fail) { console.error("exposure-events validation FAILED"); process.exit(1); }
console.log("exposure-events validation passed");
