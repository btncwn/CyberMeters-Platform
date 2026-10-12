#!/usr/bin/env node
//
// Customer hostname lists (migration 117): a workspace admin lists hostnames
// under a verified domain; every durable scan asks DNS about each one and a
// name joins discovery only when DNS answers for it.
//
// Deterministic: D1 is node:sqlite with the real migration; DNS is injected;
// the scan engine runs against mocked fetch, D1 and R2. No network.
//
// Proves: parsing keeps only in-scope hostnames and never stores the upload;
// tenant, role and verified-domain gating on every route, with foreign and
// unverified domains refused alike; append-only history (save supersedes,
// clear marks cleared) with an audit event only for writes that happened; a
// stored row can never widen scope; scans confirm listed names by DNS, flag
// rather than filter wildcard-shaped answers, and record them as "customer
// list" assets; the waitUntil path and a workspace without a list say so.
// In-memory mutants of the engine module must each be rejected.
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const srcPath = (...p) => path.join(root, "workers", "scan-api", "src", ...p);
const src = (...p) => pathToFileURL(srcPath(...p)).href;
const modulePath = srcPath("engines", "discovery-hostname-list.js");
const moduleSource = fs.readFileSync(modulePath, "utf8");
const { discoveryHostnameListRoutes } = await import(src("routes", "discovery-hostname-lists.js"));

let pass = 0, fail = 0;
const ok = (name, condition, detail = "") => {
  if (condition) pass++;
  else { fail++; console.log(`FAIL ${name}${detail ? ` — ${detail}` : ""}`); }
};
const eq = (name, got, want) => ok(name, JSON.stringify(got) === JSON.stringify(want), `got ${JSON.stringify(got)} want ${JSON.stringify(want)}`);

// ── Storage harness (real migration on node:sqlite) ─────────────────────────
function createDb() {
  const db = new DatabaseSync(":memory:");
  db.exec(`
    CREATE TABLE workspaces (id TEXT PRIMARY KEY, deleted_at TEXT);
    CREATE TABLE domains (id TEXT PRIMARY KEY, domain TEXT);
    CREATE TABLE workspace_domains (workspace_id TEXT, domain_id TEXT, verification_status TEXT, verified_at TEXT);
    CREATE TABLE audit_events (id TEXT, workspace_id TEXT, user_id TEXT, actor_type TEXT, event_type TEXT, entity_type TEXT,
      entity_id TEXT, description TEXT, metadata_json TEXT, created_at TEXT);
  `);
  db.exec(fs.readFileSync(path.join(root, "database", "migrations", "117-discovery-hostname-lists.sql"), "utf8"));
  db.prepare("INSERT INTO domains VALUES ('d1','acme.test'), ('d2','other.test'), ('d3','unverified.test')").run();
  db.prepare("INSERT INTO workspaces VALUES ('ws_a',NULL), ('ws_b',NULL)").run();
  db.prepare("INSERT INTO workspace_domains VALUES ('ws_a','d1','verified','2026-01-01'), ('ws_b','d2','verified','2026-01-01'), ('ws_a','d3','pending',NULL)").run();
  return db;
}
function d1(db) {
  const prepare = (sql) => {
    const st = db.prepare(sql);
    const bound = (...a) => ({
      _run: () => ({ meta: { changes: Number(st.run(...a).changes) } }),
      all: async () => ({ results: st.all(...a) }),
      first: async () => st.get(...a) ?? null,
      run: async () => ({ meta: { changes: Number(st.run(...a).changes) } }),
    });
    return { bind: (...a) => bound(...a), first: async () => bound().first(), all: async () => bound().all() };
  };
  return { prepare, async batch(list) { db.exec("BEGIN"); try { const r = list.map((x) => x._run()); db.exec("COMMIT"); return r; } catch (e) { db.exec("ROLLBACK"); throw e; } } };
}
const USERS = { owner: { id: "u_owner" }, admin: { id: "u_admin" }, viewer: { id: "u_viewer" }, outsider: { id: "u_out" } };
const ROLES = { u_owner: "owner", u_admin: "admin", u_viewer: "viewer" };
const PERMS = { owner: ["workspace:read", "domain:import"], admin: ["workspace:read", "domain:import"], viewer: ["workspace:read"] };
function harness(db, { limit = null } = {}) {
  const env = { cybermeters_db: d1(db) };
  const calls = { rate: [] };
  const call = async (method, p, { user = USERS.owner, body, raw, contentType = "application/json", ws = "ws_a" } = {}) => {
    const request = new Request(`https://api.example/api/workspaces/${ws}/attack-surface/hostname-lists${p}`, {
      method, headers: body !== undefined || raw !== undefined ? { "content-type": contentType } : {},
      body: raw !== undefined ? raw : body !== undefined ? JSON.stringify(body) : undefined,
    });
    const res = await discoveryHostnameListRoutes({
      request, env, url: new URL(request.url), json: (b, s = 200) => Response.json(b, { status: s }),
      requireAuth: async () => user,
      requireWorkspaceRole: async (u, wsId, perm) => {
        const role = u && wsId === "ws_a" ? ROLES[u.id] : null;
        return role && PERMS[role].includes(perm) ? { role } : null;
      },
      consumeApiRateLimit: async (_env, scopes, action, max, windowSec, opts) => { calls.rate.push([action, max, opts]); return limit?.(action) || null; },
    });
    return [res.status, await res.json()];
  };
  return { env, call, calls };
}
const rows = (db) => db.prepare("SELECT * FROM discovery_hostname_lists ORDER BY created_at, rowid").all();
const audits = (db) => db.prepare("SELECT event_type, metadata_json FROM audit_events ORDER BY rowid").all();

// ── 1. Parsing ──────────────────────────────────────────────────────────────
const engine = await import(pathToFileURL(modulePath).href);
{
  const { parseHostnameList, HOSTNAME_LIST_LIMITS } = engine;
  const plain = parseHostnameList("# our hosts\nportal.acme.test\nVPN.acme.test.\nacme.test\n*.dev.acme.test\nevil.example\nbad host\n", { format: "list", domain: "acme.test" });
  eq("parse: only in-scope hostnames, normalised and sorted", plain.hostnames, ["portal.acme.test", "vpn.acme.test"]);
  eq("parse: out-of-scope and unreadable entries are counted", [plain.summary.out_of_scope, plain.summary.rejected > 0], [1, true]);
  const csv = parseHostnameList("name,owner\nmail.acme.test,it\n\"shop.acme.test\",sales\n", { format: "csv", domain: "acme.test" });
  eq("parse: CSV hostname column", csv.hostnames, ["mail.acme.test", "shop.acme.test"]);
  const zone = parseHostnameList("$ORIGIN acme.test.\n$TTL 300\n@ IN SOA ns1 hostmaster 1 2 3 4 5\nwww IN A 192.0.2.1\nbilling 300 IN CNAME app.vendor.test.\n_dmarc IN TXT \"v=DMARC1\"\n", { format: "zone", domain: "acme.test" });
  eq("parse: zone owner names, never record data", zone.hostnames, ["billing.acme.test", "www.acme.test"]);
  const many = parseHostnameList(Array.from({ length: 250 }, (_, i) => `h${String(i).padStart(3, "0")}.acme.test`).join("\n"), { format: "list", domain: "acme.test" });
  ok("parse: at most 200 hostnames, truncation stated", many.hostnames.length === HOSTNAME_LIST_LIMITS.maxHostnames && many.summary.truncated === true);
  for (const [label, run, code] of [
    ["unsupported format", () => parseHostnameList("a.acme.test", { format: "xlsx", domain: "acme.test" }), "unsupported_format"],
    ["oversized upload", () => parseHostnameList("a".repeat(HOSTNAME_LIST_LIMITS.maxInputBytes + 1), { format: "list", domain: "acme.test" }), "input_too_large"],
    ["non-text input", () => parseHostnameList(42, { format: "list", domain: "acme.test" }), "unsupported_input"],
  ]) {
    let code_ = null;
    try { run(); } catch (error) { code_ = error.code; }
    eq(`parse: ${label} refused`, code_, code);
  }
}

// ── 2. Routes and storage ───────────────────────────────────────────────────
const LIST = { format: "list", text: "portal.acme.test\nvpn.acme.test\nsecret-note-not-a-host\nfoo.other.test\n" };
{
  const db = createDb();
  const h = harness(db);
  eq("route: unauthenticated 401", (await h.call("GET", "", { user: null }))[0], 401);
  eq("route: non-member 403", (await h.call("GET", "", { user: USERS.outsider }))[0], 403);
  eq("route: other tenant's workspace 403", (await h.call("GET", "", { ws: "ws_b" }))[0], 403);
  const [s0, list0] = await h.call("GET", "", { user: USERS.viewer });
  eq("route: viewer reads verified domains only, cannot manage", [s0, list0.can_manage, list0.domains], [200, false, [{ domain: "acme.test", list: null }]]);
  eq("route: viewer cannot save", (await h.call("PUT", "/acme.test", { user: USERS.viewer, body: LIST }))[1].code, "role_required");
  eq("route: unverified domain 403", (await h.call("PUT", "/unverified.test", { body: LIST }))[1].code, "domain_not_verified");
  eq("route: other tenant's domain gets the same 403", (await h.call("PUT", "/other.test", { body: LIST }))[1].code, "domain_not_verified");
  eq("route: non-JSON 400", (await h.call("PUT", "/acme.test", { raw: "portal.acme.test", contentType: "text/plain" }))[0], 400);
  eq("route: unknown field 400", (await h.call("PUT", "/acme.test", { body: { ...LIST, consent: true } }))[1].code, "unsupported_input");
  eq("route: malformed domain 400", (await h.call("PUT", "/acme..test", { body: LIST }))[0], 400);
  const [s422, none] = await h.call("PUT", "/acme.test", { body: { format: "list", text: "a.other.test\nb.other.test\n" } });
  eq("route: a list with nothing in scope is refused with its summary", [s422, none.code, none.result.out_of_scope], [422, "no_hostnames_accepted", 2]);
  eq("route: a refused list stores nothing and audits nothing", [rows(db).length, audits(db).length], [0, 0]);

  const [s1, saved] = await h.call("PUT", "/acme.test", { body: LIST });
  eq("route: saved", [s1, saved.list.hostnames, saved.result.accepted, saved.result.out_of_scope], [200, ["portal.acme.test", "vpn.acme.test"], 2, 2]);
  const dump = JSON.stringify(db.prepare("SELECT * FROM discovery_hostname_lists").all());
  ok("storage: the upload itself is never stored", !dump.includes("secret-note-not-a-host") && !dump.includes("foo.other.test"));
  eq("storage: one active row", rows(db).map((r) => r.status), ["active"]);
  eq("audit: save recorded with counts only", audits(db).map((a) => [a.event_type, JSON.parse(a.metadata_json).hostname_count]), [["discovery_hostname_list_saved", 2]]);
  ok("route: writes consume the workspace change limit, fail-closed",
    h.calls.rate.every(([action, max, opts]) => action === "discovery_hostname_list_change" && max === 30 && opts?.failClosed === true) && h.calls.rate.length > 0);

  const [, replaced] = await h.call("PUT", "/acme.test", { user: USERS.admin, body: { format: "csv", text: "hostname\nmail.acme.test\n" } });
  eq("history: a new save supersedes the active list", rows(db).map((r) => [r.status, r.ended_by]), [["superseded", "u_admin"], ["active", null]]);
  eq("route: the replacement is what is listed", replaced.list.hostnames, ["mail.acme.test"]);
  let duplicate = null;
  try { db.prepare("INSERT INTO discovery_hostname_lists (id,workspace_id,domain_id,status,import_format,hostnames_json,hostname_count,created_by,created_at) VALUES ('x','ws_a','d1','active','list','[\"a.acme.test\"]',1,'u','t')").run(); }
  catch (error) { duplicate = error; }
  ok("storage: at most one active list per workspace domain", duplicate !== null);
  const [, listed] = await h.call("GET", "");
  eq("route: GET returns the active list", listed.domains[0].list.hostnames, ["mail.acme.test"]);

  const [sd, cleared] = await h.call("DELETE", "/acme.test");
  eq("route: clear", [sd, cleared.cleared], [200, true]);
  eq("history: clearing keeps the row as cleared", rows(db).map((r) => r.status), ["superseded", "cleared"]);
  eq("route: clearing again changes nothing", (await h.call("DELETE", "/acme.test"))[1].cleared, false);
  eq("audit: every write that happened, and only those", audits(db).map((a) => a.event_type),
    ["discovery_hostname_list_saved", "discovery_hostname_list_saved", "discovery_hostname_list_cleared"]);

  // A rate-limited write changes nothing.
  const limited = harness(db, { limit: () => ({ status: 429, body: { error: "rate_limit_exceeded" } }) });
  eq("route: rate-limited save refused", (await limited.call("PUT", "/acme.test", { body: LIST }))[0], 429);
  eq("route: rate-limited save stored nothing", rows(db).length, 2);

  // Verification and workspace liveness are re-checked inside the write itself.
  await h.call("PUT", "/acme.test", { body: LIST });
  db.prepare("UPDATE workspace_domains SET verification_status = 'pending', verified_at = NULL WHERE workspace_id = 'ws_a' AND domain_id = 'd1'").run();
  let code = null;
  try {
    await engine.saveHostnameList(d1(db), { workspaceId: "ws_a", domainId: "d1", domain: "acme.test", userId: "u_owner",
      parsed: engine.parseHostnameList("new.acme.test", { format: "list", domain: "acme.test" }) });
  } catch (error) { code = error.code; }
  eq("storage: a save for a no-longer-verified domain is refused", code, "domain_not_verified");
  eq("storage: a refused save leaves the active list untouched", rows(db).filter((r) => r.status === "active").map((r) => r.hostname_count), [2]);
  const scanEnv = { cybermeters_db: d1(db) };
  eq("scan load: an unverified domain's list is not checked", await engine.loadActiveHostnames(scanEnv, { workspaceId: "ws_a", domainId: "d1", domain: "acme.test" }), []);
  db.prepare("UPDATE workspace_domains SET verification_status = 'verified', verified_at = '2026-01-01' WHERE workspace_id = 'ws_a' AND domain_id = 'd1'").run();
  eq("scan load: the active list of a verified domain", await engine.loadActiveHostnames(scanEnv, { workspaceId: "ws_a", domainId: "d1", domain: "acme.test" }), ["portal.acme.test", "vpn.acme.test"]);
  eq("scan load: another workspace never sees it", await engine.loadActiveHostnames(scanEnv, { workspaceId: "ws_b", domainId: "d1", domain: "acme.test" }), []);
  db.prepare("UPDATE discovery_hostname_lists SET hostnames_json = '[\"portal.acme.test\",\"evil.example\",\"acme.test\"]' WHERE status = 'active'").run();
  eq("scan load: a stored row can never widen scope", await engine.loadActiveHostnames(scanEnv, { workspaceId: "ws_a", domainId: "d1", domain: "acme.test" }), ["portal.acme.test"]);
  db.prepare("UPDATE workspaces SET deleted_at = '2026-10-01' WHERE id = 'ws_a'").run();
  eq("scan load: a deleted workspace's list is not checked", await engine.loadActiveHostnames(scanEnv, { workspaceId: "ws_a", domainId: "d1", domain: "acme.test" }), []);
  eq("route: a deleted workspace is not found", (await h.call("GET", ""))[0], 404);
  eq("scan load: a failed read is reported, not read as an empty list",
    await engine.loadActiveHostnames({ cybermeters_db: { prepare: () => { throw new Error("d1 down"); } } }, { workspaceId: "ws_a", domainId: "d1", domain: "acme.test" }), null);
}

// ── 3. Confirmation ─────────────────────────────────────────────────────────
const answer = (name, ip) => ({ Status: 0, Answer: [{ name, type: 1, TTL: 60, data: ip }] });
async function confirmationFixtures(api) {
  let checks = 0;
  const asked = [];
  const result = await api.confirmListedHostnames("acme.test",
    ["portal.acme.test", "vpn.acme.test", "old.acme.test", "mx-only.acme.test", "flaky.acme.test", "wild.acme.test", "known.acme.test", "evil.example"], {
      exclude: ["known.acme.test"], wildcardAddresses: ["198.51.100.9"],
      lookup: async (name) => {
        asked.push(name);
        if (name === "flaky.acme.test") throw new Error("network down");
        return name === "portal.acme.test" ? answer(name, "203.0.113.5")
          : name === "vpn.acme.test" ? { Status: 0, Answer: [{ name, type: 5, TTL: 60, data: "vpn.vendor.test." }] }
          : name === "wild.acme.test" ? answer(name, "198.51.100.9")
          : name === "mx-only.acme.test" ? { Status: 0, Answer: [] }
          : { Status: 3, Answer: [] };
      },
    });
  assert.deepEqual(asked.sort(), ["flaky.acme.test", "mx-only.acme.test", "old.acme.test", "portal.acme.test", "vpn.acme.test", "wild.acme.test"], "only in-scope names not already discovered are asked"); checks++;
  assert.deepEqual(result.confirmed.map((item) => [item.hostname, item.source]),
    [["portal.acme.test", "customer_list"], ["vpn.acme.test", "customer_list"], ["wild.acme.test", "customer_list"]], "only names DNS answers for are confirmed"); checks++;
  assert.equal(result.confirmed.find((item) => item.hostname === "wild.acme.test")?.wildcard_match, true, "a listed name with a wildcard-shaped answer is flagged, not filtered"); checks++;
  assert.equal(result.confirmed.find((item) => item.hostname === "vpn.acme.test")?.alias_only, true, "an alias without an address is confirmed alias-only"); checks++;
  assert.deepEqual([result.listed, result.already_discovered, result.not_found, result.no_address, result.lookup_failed], [7, 1, 1, 1, 1], "every listed name is accounted for"); checks++;
  assert.equal(result.incomplete_reason, "lookup_failed", "a failed lookup leaves the step incomplete"); checks++;
  let ticks = 0;
  const slow = await api.confirmListedHostnames("acme.test", Array.from({ length: 60 }, (_, i) => `n${i}.acme.test`), {
    clock: () => (ticks++ < 2 ? 0 : 1e12), lookup: async (name) => answer(name, "203.0.113.6"),
  });
  assert.ok(slow.not_asked > 0 && slow.incomplete_reason === "time_budget_reached", "names left unasked when the soft budget is spent are stated"); checks++;
  const none = api.customerHostnamesNotExecuted("no_list");
  assert.ok(none.executed === false && none.incomplete === false, "no list is not a gap"); checks++;
  const skipped = api.customerHostnamesNotExecuted("invocation_not_durable", 4);
  assert.ok(skipped.incomplete === true && skipped.listed === 4 && skipped.confirmed.length === 0, "a step that did not run claims nothing"); checks++;
  return checks;
}
try { pass += await confirmationFixtures(engine); } catch (error) { fail++; console.log(`FAIL confirmation fixtures — ${error.message}`); }

const dataUrl = (source) => `data:text/javascript;base64,${Buffer.from(source).toString("base64")}`;
const absoluteImports = (source) => source.replace(/from "(\.\.?\/[^"]+)"/g,
  (_, rel) => `from "${pathToFileURL(path.join(path.dirname(modulePath), rel)).href}"`);
const MUTANTS = [
  ["if (item.kind === \"candidate\") names.add(item.hostname);", "names.add(String(value));", "stored names skip the scope check"],
  ["const confirmation = confirmationOf(observation, { wildcardSet, filterWildcard: false });",
    "const confirmation = confirmationOf(observation, { wildcardSet, filterWildcard: true });", "listed names are wildcard-filtered"],
  ["const pending = listed.filter((hostname) => !known.has(hostname));", "const pending = listed;", "discovered names are asked again"],
  ["if (unasked > 0) reasons.push(\"time_budget_reached\");", "", "names left unasked are hidden"],
  ["const gap = reason !== \"no_list\";", "const gap = false;", "a step that did not run is not a gap"],
];
for (const [before, after, label] of MUTANTS) {
  ok(`mutant anchor is unique: ${label}`, moduleSource.split(before).length === 2);
  let killed = false;
  try {
    const mutant = await import(dataUrl(absoluteImports(moduleSource.replace(before, after))));
    await confirmationFixtures(mutant);
    // Scope on stored rows is proven through the real read path.
    const db = createDb();
    db.prepare("INSERT INTO discovery_hostname_lists (id,workspace_id,domain_id,status,import_format,hostnames_json,hostname_count,created_by,created_at) VALUES ('x','ws_a','d1','active','list','[\"portal.acme.test\",\"evil.example\"]',2,'u','t')").run();
    assert.deepEqual(await mutant.loadActiveHostnames({ cybermeters_db: d1(db) }, { workspaceId: "ws_a", domainId: "d1", domain: "acme.test" }), ["portal.acme.test"]);
  } catch (error) { killed = error instanceof assert.AssertionError; }
  ok(`mutant rejected: ${label}`, killed);
}
// Write-side guard mutants: the verified/live predicate on both writes.
{
  const guarded = moduleSource.split("AND ${LIVE_VERIFIED}`)").length - 1 + moduleSource.split("WHERE ${LIVE_VERIFIED}`)").length - 1;
  eq("writes: supersede and insert both repeat the live, verified predicate", guarded, 2);
  ok("writes: the audit row selects the inserted list", /SELECT 1 FROM discovery_hostname_lists WHERE id = \? AND workspace_id = \?/.test(moduleSource));
}

// ── 4. Wiring ───────────────────────────────────────────────────────────────
const index = fs.readFileSync(srcPath("index.js"), "utf8");
ok("router: hostname list routes mounted", /discoveryHostnameListRoutes\(routeCtx\)/.test(index));
ok("purge: the table is purged with the workspace", /WORKSPACE_PURGE_TABLES = \[[\s\S]*"discovery_hostname_lists"[\s\S]*?\];/.test(index));
const unlink = fs.readFileSync(srcPath("routes", "workspaces-core.js"), "utf8");
ok("unlink: removing the domain clears its active list",
  /UPDATE discovery_hostname_lists SET status = 'cleared'[\s\S]{0,200}WHERE workspace_id = \? AND domain_id = \? AND status = 'active'/.test(unlink));
const { assetSourceLabel } = await import(pathToFileURL(path.join(root, "frontend", "src", "lib", "assetSourceLabel.js")).href);
ok("label: listed assets have customer wording", assetSourceLabel(engine.HOSTNAME_LIST_ASSET_SOURCE) === "Listed by you");
const shadow = fs.readFileSync(srcPath("engines", "shadow-it-inventory.js"), "utf8");
ok("Shadow IT treats listed assets as discovery evidence", /const DISCOVERY_ASSET_SOURCES = new Set\(\[[^\]]*HOSTNAME_LIST_ASSET_SOURCE,[^\]]*\]\);/.test(shadow));
const { OUTBOUND_FULLY_INSTRUMENTED_MODULES } = await import(src("engines", "scan-budget.js"));
ok("the confirmation step's outbound calls are fully instrumented", OUTBOUND_FULLY_INSTRUMENTED_MODULES.has("customer_hostnames"));

// ── 5. Real engine traces ───────────────────────────────────────────────────
const { runScanEngine } = await import(src("engines", "scan-engine.js"));
const realFetch = globalThis.fetch;
async function traceEngine(executionContext, { listed = ["ledger7.acme.test", "gone.acme.test"] } = {}) {
  const dnsQuestions = [];
  const inserts = [];
  let report = null;
  globalThis.fetch = async (input) => {
    const url = new URL(String(input));
    if (url.hostname === "cloudflare-dns.com" || url.hostname === "dns.google") {
      const name = url.searchParams.get("name") || "";
      const type = url.searchParams.get("type") || "A";
      dnsQuestions.push(`${type} ${name}`);
      if (type === "A" && ["acme.test", "www.acme.test", "ledger7.acme.test"].includes(name)) {
        return Response.json({ Status: 0, Answer: [{ name, type: 1, TTL: 60, data: "203.0.113.70" }] });
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
    sql, args,
    bind: (...bound) => statement(sql, bound),
    run: async () => ({ success: true, meta: { changes: /INSERT OR IGNORE INTO scan_report_snapshots|SET status = 'completed'/.test(sql) ? 1 : 0 } }),
    all: async () => ({ results: /FROM workspace_domains wd\s+JOIN workspaces w/.test(sql) ? [{ workspace_id: "ws_list" }] : [] }),
    first: async () => (/SELECT id FROM workspaces WHERE id = \? AND deleted_at IS NULL/.test(sql) ? { id: args[0] }
      : /FROM discovery_hostname_lists l/.test(sql) && args[0] === "ws_list" && args[1] === "dom_list" && listed
        ? { hostnames_json: JSON.stringify(listed) } : null),
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
      put: async (key, body) => { r2.set(String(key), String(body)); if (String(key) === "reports/scan_list.json") report = JSON.parse(String(body)); return {}; },
      get: async (key) => (r2.has(String(key)) ? { text: async () => r2.get(String(key)), json: async () => JSON.parse(r2.get(String(key))) } : null),
      delete: async () => ({}),
    },
    APP_VERSION: "test",
  };
  let threw = null;
  try { await runScanEngine("scan_list", "dom_list", "ws_list", "acme.test", env, { executionContext }); } catch (error) { threw = error; }
  globalThis.fetch = realFetch;
  return { threw, report, dnsQuestions, inserts };
}
const durable = await traceEngine("queue");
const step = durable.report?.modules?.subdomains?.customer_hostnames;
ok("durable trace completes", durable.threw === null && durable.report !== null, String(durable.threw));
ok("durable: a listed name DNS answers for is confirmed; one that does not exist is counted",
  JSON.stringify(step?.confirmed?.map((item) => item.hostname)) === JSON.stringify(["ledger7.acme.test"]) && step?.not_found === 1,
  JSON.stringify(step));
ok("durable: the confirmed name joins discovery and takeover checks",
  (durable.report?.modules?.subdomains?.items || []).includes("ledger7.acme.test") && durable.dnsQuestions.includes("CNAME ledger7.acme.test") &&
    !(durable.report?.modules?.subdomains?.items || []).includes("gone.acme.test"));
ok("durable: the inventory records it as listed by the customer",
  durable.inserts.some((row) => row.hostname === "ledger7.acme.test" && row.source === "customer_list") &&
    !durable.inserts.some((row) => row.hostname === "gone.acme.test"), JSON.stringify(durable.inserts));
ok("durable: discovery names the listed step as a source",
  (durable.report?.modules?.attack_surface_signal_completeness?.signals?.subdomain_discovery?.sources || []).includes("customer_hostnames"));
const compact = await traceEngine("waituntil");
ok("waitUntil: the step states it did not run and asks nothing",
  compact.report?.modules?.subdomains?.customer_hostnames?.reason === "invocation_not_durable" &&
    !compact.dnsQuestions.includes("A gone.acme.test"));
const noList = await traceEngine("queue", { listed: null });
ok("no list: the step says there was nothing to check, without a gap",
  noList.report?.modules?.subdomains?.customer_hostnames?.reason === "no_list" &&
    noList.report?.modules?.subdomains?.customer_hostnames?.incomplete === false);

console.log(`\ndiscovery hostname list: ${pass} passed, ${fail} failed`);
process.exit(fail === 0 ? 0 : 1);
