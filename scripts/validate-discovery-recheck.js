#!/usr/bin/env node
//
// Known-host re-checks rotate through the whole inventory, and every known
// host gets the subdomain-takeover check.
//
// Proves, with the real loader on node:sqlite and the real scan engine:
//   • the 50 re-check slots go to the names checked least recently — when a
//     scan last actually re-checked them — so an inventory larger than the cap
//     is fully covered over successive scans;
//   • every scan writes a lifecycle row for every asset, including the names it
//     did not check ("not_assessed"); those rows are not checks and never push
//     a name back in the queue (they once made every name look checked today,
//     collapsing the rotation into alphabetical order);
//   • a name discovery saw but no scan checked is still due;
//   • re-check observations outside the window do not count, deleted
//     workspaces and the root never become targets, and ties are stable;
//   • a scan asks the takeover CNAME question for inventory hosts that this
//     scan did not rediscover.
import fs from "node:fs";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const src = (...p) => pathToFileURL(path.join(root, "workers", "scan-api", "src", ...p)).href;
const { loadKnownAssetRecheckHosts, RECHECK_OBSERVATION_WINDOW_DAYS } = await import(src("engines", "attack-surface-lifecycle.js"));

let pass = 0, fail = 0;
const ok = (name, condition, detail = "") => {
  if (condition) pass++;
  else { fail++; console.log(`FAIL ${name}${detail ? ` — ${detail}` : ""}`); }
};
const eq = (name, got, want) => ok(name, JSON.stringify(got) === JSON.stringify(want), `got ${JSON.stringify(got)} want ${JSON.stringify(want)}`);

function d1(db) {
  return {
    prepare: (sql) => {
      const st = db.prepare(sql);
      return { bind: (...a) => ({ all: async () => ({ results: st.all(...a) }), first: async () => st.get(...a) ?? null }) };
    },
  };
}
const DAY = 86_400_000;
const NOW = Date.parse("2026-10-12T12:00:00.000Z");
const iso = (daysAgo) => new Date(NOW - daysAgo * DAY).toISOString();

const db = new DatabaseSync(":memory:");
db.exec(`
  CREATE TABLE workspaces (id TEXT PRIMARY KEY, deleted_at TEXT);
  CREATE TABLE workspace_domains (workspace_id TEXT, domain_id TEXT);
  CREATE TABLE workspace_assets (id TEXT PRIMARY KEY, workspace_id TEXT, domain_id TEXT, hostname TEXT, last_seen TEXT);
  CREATE TABLE asset_lifecycle_observations (id TEXT PRIMARY KEY, workspace_id TEXT, asset_id TEXT, observation_state TEXT, observed_at TEXT);
  INSERT INTO workspaces VALUES ('ws', NULL), ('ws_gone', '2026-10-01T00:00:00.000Z');
  INSERT INTO workspace_domains VALUES ('ws', 'dom'), ('ws_gone', 'dom');
`);
// 60 known names, all last seen by discovery 10 days ago.
const insertAsset = db.prepare("INSERT INTO workspace_assets VALUES (?, ?, 'dom', ?, ?)");
for (let i = 0; i < 60; i++) insertAsset.run(`a${i}`, "ws", `h${String(i).padStart(2, "0")}.example.com`, iso(10));
insertAsset.run("root", "ws", "example.com", iso(40));
insertAsset.run("deleted", "ws_gone", "only-deleted.example.com", iso(50));
const env = { cybermeters_db: d1(db) };
const load = () => loadKnownAssetRecheckHosts(env, "dom", "example.com", { now: NOW });
const observe = (hosts, daysAgo, state = "observed") => {
  const insert = db.prepare("INSERT INTO asset_lifecycle_observations VALUES (?, 'ws', ?, ?, ?)");
  for (const host of hosts) {
    const asset = db.prepare("SELECT id FROM workspace_assets WHERE hostname = ? AND workspace_id = 'ws'").get(host);
    insert.run(`o_${host}_${daysAgo}_${state}_${Math.random()}`, asset.id, state, iso(daysAgo));
  }
};
const allHosts = Array.from({ length: 60 }, (_, i) => `h${String(i).padStart(2, "0")}.example.com`);

const first = await load();
eq("cap: at most 50 names", first.length, 50);
ok("scope: never the root, never a deleted workspace's name", !first.includes("example.com") && !first.includes("only-deleted.example.com"));
eq("ties: equal recency falls back to hostname order", first.slice(0, 3), ["h00.example.com", "h01.example.com", "h02.example.com"]);

// Scan 1 (two days ago) re-checks its 50; scan 2 must start with the 10 it
// could not reach. Like production, the scan also writes a "not_assessed" row
// for the 10 names it did not check.
observe(first, 2);
observe(allHosts.filter((host) => !first.includes(host)), 2, "not_assessed");
const second = await load();
eq("rotation: the names left out last time come first", second.slice(0, 10), Array.from({ length: 10 }, (_, i) => `h${50 + i}.example.com`));
const covered = new Set([...first, ...second]);
eq("rotation: two scans cover the whole 60-name inventory", covered.size, 60);

// Scan 2 (yesterday) checks its 50, one of them measured as unavailable, and
// writes "not_assessed" for the rest. Today discovery sees one of those rest.
observe(second.filter((host) => host !== "h52.example.com"), 1);
observe(["h52.example.com"], 1, "observation_unavailable");
observe(allHosts.filter((host) => !second.includes(host)), 1, "not_assessed");
db.prepare("UPDATE workspace_assets SET last_seen = ? WHERE hostname = 'h45.example.com'").run(iso(0));
const third = await load();
const stale = allHosts.filter((host) => !second.includes(host));
eq("recency: the names checked longest ago come first", third.slice(0, stale.length), stale);
ok("recency: a name discovery saw today but no scan checked is still due", third.slice(0, stale.length).includes("h45.example.com"), JSON.stringify(third.slice(0, 12)));
ok("recency: a check that measured the name as unavailable still counts as a check", third.indexOf("h52.example.com") === -1 || third.indexOf("h52.example.com") >= stale.length, JSON.stringify(third.slice(0, 12)));

// A re-check older than the window does not count as recent.
observe(allHosts, 0);
db.prepare("DELETE FROM asset_lifecycle_observations WHERE asset_id = 'a30'").run();
observe(["h30.example.com"], RECHECK_OBSERVATION_WINDOW_DAYS + 5);
const fourth = await load();
ok("window: a re-check outside the observation window leaves the name due", fourth[0] === "h30.example.com", JSON.stringify(fourth.slice(0, 3)));
// The production pattern: every scan writes a row for every asset. Rows for
// names a scan did not check must not make them look checked.
db.prepare("DELETE FROM asset_lifecycle_observations").run();
for (let scan = 0; scan < 3; scan++) {
  observe(allHosts.slice(0, 50), 3 - scan);
  observe(allHosts.slice(50), 3 - scan, "not_assessed");
}
const fifth = await load();
eq("rotation: names only ever written as not assessed come first", fifth.slice(0, 10), allHosts.slice(50));
eq("failure: a failed read yields no targets, not an error",
  await loadKnownAssetRecheckHosts({ cybermeters_db: { prepare: () => { throw new Error("d1 down"); } } }, "dom", "example.com"), []);

// ── Engine: every known host gets the takeover CNAME question ───────────────
const { runScanEngine } = await import(src("engines", "scan-engine.js"));
const realFetch = globalThis.fetch;
const dnsQuestions = [];
globalThis.fetch = async (input) => {
  const url = new URL(String(input));
  if (url.hostname === "cloudflare-dns.com" || url.hostname === "dns.google") {
    const name = url.searchParams.get("name") || "";
    const type = url.searchParams.get("type") || "A";
    dnsQuestions.push(`${type} ${name}`);
    if (type === "A" && ["example.com", "www.example.com"].includes(name)) {
      return Response.json({ Status: 0, Answer: [{ name, type: 1, TTL: 60, data: "203.0.113.80" }] });
    }
    return Response.json({ Status: 3, Answer: [] });
  }
  if (url.protocol === "https:" || url.protocol === "http:") {
    return new Response("<html><title>Site</title></html>", { status: 200, headers: { "content-type": "text/html" } });
  }
  return Response.json({});
};
const statement = (sql, args = []) => ({
  bind: (...bound) => statement(sql, bound),
  run: async () => ({ success: true, meta: { changes: /INSERT OR IGNORE INTO scan_report_snapshots|SET status = 'completed'/.test(sql) ? 1 : 0 } }),
  all: async () => ({ results: /AS last_checked\s+FROM workspace_assets wa/.test(sql) ? [{ hostname: "legacy-shop.example.com" }] : [] }),
  first: async () => (/SELECT id FROM workspaces WHERE id = \? AND deleted_at IS NULL/.test(sql) ? { id: args[0] } : null),
});
const r2 = new Map();
let report = null;
const engineEnv = {
  cybermeters_db: { prepare: (sql) => statement(sql), batch: async (list) => list.map(() => ({ results: [], meta: { changes: 0 } })) },
  cybermeters_reports: {
    put: async (key, body) => { r2.set(String(key), String(body)); if (String(key) === "reports/scan_recheck.json") report = JSON.parse(String(body)); return {}; },
    get: async (key) => (r2.has(String(key)) ? { text: async () => r2.get(String(key)), json: async () => JSON.parse(r2.get(String(key))) } : null),
    delete: async () => ({}),
  },
  APP_VERSION: "test",
};
let threw = null;
try { await runScanEngine("scan_recheck", "dom", "ws", "example.com", engineEnv, { executionContext: "queue" }); } catch (error) { threw = error; }
globalThis.fetch = realFetch;
ok("engine trace completes", threw === null && report !== null, String(threw));
ok("engine: a known host this scan did not rediscover still gets the takeover check",
  !(report?.modules?.subdomains?.items || []).includes("legacy-shop.example.com") &&
    dnsQuestions.includes("CNAME legacy-shop.example.com"),
  dnsQuestions.filter((q) => q.startsWith("CNAME")).join(", "));
const engineSource = fs.readFileSync(path.join(root, "workers", "scan-api", "src", "engines", "scan-engine.js"), "utf8");
ok("engine: takeover input is this scan's discoveries, then the inventory",
  /runTakeoverModule\(domain, \[\.\.\.discoveryHosts, \.\.\.knownAssetHosts\],/.test(engineSource));

console.log(`\ndiscovery recheck: ${pass} passed, ${fail} failed`);
process.exit(fail === 0 ? 0 : 1);
