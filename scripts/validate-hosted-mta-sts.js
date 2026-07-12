#!/usr/bin/env node
//
// Hosted MTA-STS regression (guided-hybrid, on hosted_dns_entries).
// Proves record_kind='mtasts' can host only the _mta-sts TXT policy id while
// the customer-hosted HTTPS policy file is verified independently. Node 24+.
//
import fs from "node:fs";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const eng = await import(pathToFileURL(path.join(root, "workers", "scan-api", "src", "engines", "hosted-dmarc.js")).href);
const { hashToken } = await import(pathToFileURL(path.join(root, "workers", "scan-api", "src", "lib", "auth-crypto.js")).href);
const {
  buildMtaStsPolicy,
  buildMtaStsTxtValue,
  hostedCustomerRecordName,
  runHostedDnsVerificationSweep,
} = eng;

let pass = 0, fail = 0;
const ok = (name, cond) => { cond ? pass++ : fail++; if (!cond) console.log("FAIL " + name); };

let mxHosts = ["mx1.acme.co.uk"];
let dnsDelegated = false;
let httpsPolicyContent = null;

function jsonResponse(body, status = 200) {
  return new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
}

function currentHostedRow(db) {
  return db.prepare("SELECT * FROM hosted_dns_entries WHERE workspace_id='ws_a' AND domain='acme.co.uk' AND record_kind='mtasts'").get();
}

async function fakeDnsQuery(name, type) {
  const row = currentHostedRow(db);
  if (type === "MX" && name === "acme.co.uk") {
    return { Status: 0, Answer: mxHosts.map((host, idx) => ({ type: 15, data: `${10 + idx} ${host}.` })) };
  }
  if (!row) return { Status: 3, Answer: [] };
  if (type === "TXT" && name === row.target_name) {
    return { Status: 0, Answer: [{ type: 16, data: row.target_value }] };
  }
  if (type === "TXT" && name === "_mta-sts.acme.co.uk") {
    if (!dnsDelegated) return { Status: 3, Answer: [] };
    return { Status: 0, Answer: [
      { type: 5, data: row.target_name },
      { type: 16, data: row.target_value },
    ] };
  }
  if (type === "CNAME" && name === "_mta-sts.acme.co.uk") {
    return dnsDelegated ? { Status: 0, Answer: [{ type: 5, data: row.target_name }] } : { Status: 3, Answer: [] };
  }
  if (type === "TXT" && name === "_dmarc.acme.co.uk") {
    return { Status: 0, Answer: [{ type: 5, data: "hd-dmarc1.dmarc.cybermeters.com" }, { type: 16, data: "v=DMARC1; p=none" }] };
  }
  if (type === "TXT" && name === "hd-dmarc1.dmarc.cybermeters.com") {
    return { Status: 0, Answer: [{ type: 16, data: "v=DMARC1; p=none" }] };
  }
  return { Status: 3, Answer: [] };
}

async function fakeFetch(input, init = {}) {
  const url = typeof input === "string" ? input : input.url;
  if (url.startsWith("https://cloudflare-dns.com/dns-query")) {
    const u = new URL(url);
    return jsonResponse(await fakeDnsQuery(u.searchParams.get("name"), u.searchParams.get("type")));
  }
  if (url.startsWith("https://api.cloudflare.com/client/v4/zones/")) {
    if (init.method === "POST") return jsonResponse({ success: true, result: { id: "cf-mtasts-1" } });
    if (init.method === "DELETE") return jsonResponse({ success: true, result: { id: "cf-mtasts-1" } });
    return jsonResponse({ success: true, result: [] });
  }
  if (url === "https://mta-sts.acme.co.uk/.well-known/mta-sts.txt") {
    if (!httpsPolicyContent) return new Response("not found", { status: 404 });
    return new Response(httpsPolicyContent, { status: 200, headers: { "content-type": "text/plain" } });
  }
  throw new Error(`unexpected fetch ${url}`);
}

globalThis.fetch = fakeFetch;
AbortSignal.timeout = () => undefined;
const worker = await import(pathToFileURL(path.join(root, "workers", "scan-api", "src", "index.js")).href);

const db = new DatabaseSync(":memory:");
const apply = (p) => { try { db.exec(fs.readFileSync(p, "utf8")); } catch { /* ordering no-ops */ } };
apply(path.join(root, "database", "schema.sql"));
for (const f of fs.readdirSync(path.join(root, "database", "migrations")).filter((f) => f.endsWith(".sql")).sort()) apply(path.join(root, "database", "migrations", f));
db.exec("PRAGMA foreign_keys = OFF");
const makeD1 = (db) => { const wrap = (sql, a) => ({ first: async () => db.prepare(sql).get(...a) ?? null, all: async () => ({ results: db.prepare(sql).all(...a) }), run: async () => { const r = db.prepare(sql).run(...a); return { meta: { changes: r.changes } }; } }); return { prepare(sql) { const b = wrap(sql, []); b.bind = (...a) => wrap(sql, a); return b; } }; };

// ── 1. Unit helpers ──────────────────────────────────────────────────────────
ok("customer name for mtasts is _mta-sts.<domain>", hostedCustomerRecordName("acme.co.uk", "mtasts") === "_mta-sts.acme.co.uk");
ok("customer name for tlsrpt remains _smtp._tls.<domain>", hostedCustomerRecordName("acme.co.uk", "tlsrpt") === "_smtp._tls.acme.co.uk");
ok("customer name for dmarc unchanged", hostedCustomerRecordName("acme.co.uk", "dmarc") === "_dmarc.acme.co.uk");
ok("MTA-STS TXT helper uses STSv1 id", buildMtaStsTxtValue("12345") === "v=STSv1; id=12345");
ok("generated policy defaults to testing and never enforce", /mode: testing/.test(buildMtaStsPolicy("acme.co.uk", ["mx1.acme.co.uk"])) && !/mode: enforce/.test(buildMtaStsPolicy("acme.co.uk", ["mx1.acme.co.uk"])));

// ── Seed: u_a (member of ws_a), ws_b owned by u_other; domain ────────────────
db.prepare("INSERT INTO users (id,email,email_verified) VALUES ('u_a','a@example.co.uk',1)").run();
db.prepare("INSERT INTO workspaces (id,name,owner_user_id) VALUES ('ws_a','Acme','u_a')").run();
db.prepare("INSERT INTO workspaces (id,name,owner_user_id) VALUES ('ws_b','Other','u_other')").run();
db.prepare("INSERT INTO workspace_members (workspace_id,user_id,role) VALUES ('ws_a','u_a','owner')").run();
db.prepare("INSERT INTO domains (id,user_id,domain) VALUES ('d_a','u_a','acme.co.uk')").run();
db.prepare("INSERT INTO workspace_domains (workspace_id,domain_id) VALUES ('ws_a','d_a')").run();

const TOKEN = "tok_a";
db.prepare("INSERT INTO user_sessions (id,user_id,token_hash,expires_at) VALUES ('s_a','u_a',?, datetime('now','+1 day'))").run(await hashToken(TOKEN));

const env = {
  cybermeters_db: makeD1(db),
  ALLOWED_ORIGIN: "https://app.cybermeters.com",
  APP_VERSION: "test",
  CLOUDFLARE_ZONE_ID: "0123456789abcdef0123456789abcdef",
  CLOUDFLARE_API_TOKEN: "cf-token",
};
const ctx = { waitUntil: () => {}, passThroughOnException: () => {} };
const call = async (method, p, token) => {
  const res = await worker.default.fetch(new Request(`https://app.cybermeters.com${p}`, { method, headers: token ? { Authorization: `Bearer ${token}` } : {} }), env, ctx);
  let body = {}; try { body = await res.json(); } catch { /* */ }
  return { status: res.status, body };
};
const BASE = "/api/workspaces/ws_a/domains/acme.co.uk/hosted-mta-sts";

// ── 2. Create + serialization ───────────────────────────────────────────────
const created = await call("POST", BASE, TOKEN);
ok("create returns 201", created.status === 201);
ok("record is record_type mtasts", created.body.record?.record_type === "mtasts");
ok("cname_name is _mta-sts.<domain>", created.body.record?.cname_name === "_mta-sts.acme.co.uk");
ok("policy path returned", created.body.record?.policy_path === "https://mta-sts.acme.co.uk/.well-known/mta-sts.txt");
ok("boundary text returned", /CyberMeters manages the MTA-STS DNS policy ID/.test(created.body.record?.boundary || ""));
ok("policy content is pinned in testing mode", /version: STSv1\nmode: testing\nmx: mx1\.acme\.co\.uk\nmax_age: 604800/.test(created.body.record?.policy_content || ""));
ok("MTA-STS is not complete before HTTPS policy verification", created.body.record?.complete === false);
ok("no DMARC ramp fields leak onto mtasts", created.body.record?.autopilot === false && created.body.record?.policy_step == null);

let row = currentHostedRow(db);
ok("row persisted record_kind=mtasts", !!row && row.record_kind === "mtasts");
ok("row policy_content persisted", /mode: testing/.test(row?.policy_content || ""));
ok("row target_value is STSv1 id", /^v=STSv1; id=\d+$/.test(row?.target_value || ""));
ok("row advanced to awaiting_cname after CF create", row?.verification_state === "awaiting_cname");
const pinnedValue = row.target_value;
const pinnedPolicy = row.policy_content;

// ── 3. Independent DNS / HTTPS verification states ──────────────────────────
dnsDelegated = true;
let verified = await call("GET", `${BASE}/verify`, TOKEN);
ok("verify with DNS delegated but HTTPS missing returns 200", verified.status === 200);
ok("DNS TXT can be connected independently", verified.body.record?.dns_txt?.state === "connected");
ok("HTTPS policy is not_published independently", verified.body.record?.https_policy?.state === "not_published");
ok("not complete until HTTPS policy is reachable and matching", verified.body.record?.complete === false);

httpsPolicyContent = pinnedPolicy;
verified = await call("GET", `${BASE}/verify`, TOKEN);
ok("HTTPS policy reachable_valid when exact pinned content is served", verified.body.record?.https_policy?.state === "reachable_valid");
ok("matching pinned policy is detected", verified.body.record?.https_policy?.matches_pinned_policy === true);
ok("complete only when DNS and HTTPS policy are both green", verified.body.record?.complete === true);
ok("success label remains testing-mode", verified.body.record?.https_policy?.mode === "testing");

// ── 4. MX drift surfaces without mutating policy/id ─────────────────────────
mxHosts = ["mx2.acme.co.uk"];
const drift = await call("GET", BASE, TOKEN);
ok("MX drift is surfaced", drift.body.record?.mx_drift?.detected === true && drift.body.record?.review_required === true);
row = currentHostedRow(db);
ok("MX drift does not mutate pinned policy", row.policy_content === pinnedPolicy);
ok("MX drift does not bump DNS policy id", row.target_value === pinnedValue);

// ── 5. Sweep lifecycle + coexistence + DMARC resolver regression ────────────
db.prepare("INSERT INTO hosted_dns_entries (id,workspace_id,domain,record_kind,customer_name,target_name,target_value,verification_state,policy_content) VALUES ('hd-sweep1','ws_a','sweep.co.uk','mtasts','_mta-sts.sweep.co.uk','hd-sweep1.dmarc.cybermeters.com','v=STSv1; id=11','pending_dns','version: STSv1\nmode: testing\nmx: *.sweep.co.uk\nmax_age: 604800')").run();
const sweep = await runHostedDnsVerificationSweep(env, { dnsQueryImpl: fakeDnsQuery, fetchImpl: fakeFetch, now: new Date("2026-07-12T12:00:00Z") });
ok("verification sweep processes hosted DNS entries", sweep.checked >= 1);
ok("sweep publishes stranded mtasts rows through the shared saga", db.prepare("SELECT provider_record_id FROM hosted_dns_entries WHERE id='hd-sweep1'").get()?.provider_record_id === "cf-mtasts-1");

db.prepare("INSERT INTO hosted_dns_entries (id,workspace_id,domain,record_kind,customer_name,target_name,target_value,verification_state) VALUES ('hd-dmarc1','ws_a','acme.co.uk','dmarc','_dmarc.acme.co.uk','hd-dmarc1.dmarc.cybermeters.com','v=DMARC1; p=none','connected')").run();
db.prepare("INSERT INTO hosted_dns_entries (id,workspace_id,domain,record_kind,customer_name,target_name,target_value,verification_state) VALUES ('hd-tlsrpt1','ws_a','acme.co.uk','tlsrpt','_smtp._tls.acme.co.uk','hd-tlsrpt1.dmarc.cybermeters.com','v=TLSRPTv1; rua=mailto:r@reports.cybermeters.com','connected')").run();
ok("DMARC + TLS-RPT + MTA-STS coexist on one domain", db.prepare("SELECT COUNT(DISTINCT record_kind) c FROM hosted_dns_entries WHERE domain='acme.co.uk'").get().c === 3);
ok("DMARC row still verifies against _dmarc", (await eng.verifyHostedDmarcRecord(db.prepare("SELECT *, verification_state AS status, target_name AS hosted_name, target_value AS current_value FROM hosted_dns_entries WHERE id='hd-dmarc1'").get(), { dnsQueryImpl: fakeDnsQuery })).cname_connected === true);

// ── 6. Delete (grace-protected removal request) + isolation ──────────────────
const del = await call("DELETE", BASE, TOKEN);
ok("delete returns 200 + pending_removal", del.status === 200 && del.body.record?.status === "pending_removal");
ok("row moved to pending_removal", db.prepare("SELECT verification_state v FROM hosted_dns_entries WHERE record_kind='mtasts' AND domain='acme.co.uk'").get().v === "pending_removal");
ok("non-member is denied another workspace (403)", (await call("POST", "/api/workspaces/ws_b/domains/acme.co.uk/hosted-mta-sts", TOKEN)).status === 403);
ok("unauthenticated is rejected (401)", (await call("GET", BASE)).status === 401);

console.log(`\nHosted MTA-STS: ${pass}/${pass + fail} passed`);
if (fail) { console.error("hosted-mta-sts validation FAILED"); process.exit(1); }
console.log("hosted-mta-sts validation passed");
