#!/usr/bin/env node
//
// Hosted TLS-RPT regression (Phase C, on the v2 hosted_dns_entries foundation).
// Proves the customer can host a TLS-RPT record via CNAME delegation: create →
// record stored as record_kind='tlsrpt' with customer_name '_smtp._tls.<domain>'
// → GET/verify/DELETE lifecycle → coexists with a DMARC entry on the same domain
// (UNIQUE is per kind) → tenant-isolated. Drives the real worker with a seeded
// session; no Cloudflare creds (create stays pending_dns) and DNS is disabled
// (verify returns not-connected) — both handled gracefully. Node 24+. CI-blocking.
//
import fs from "node:fs";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const eng = await import(pathToFileURL(path.join(root, "workers", "scan-api", "src", "engines", "hosted-dmarc.js")).href);
const { hashToken } = await import(pathToFileURL(path.join(root, "workers", "scan-api", "src", "lib", "auth-crypto.js")).href);
const { buildTlsRptValue, hostedCustomerRecordName } = eng;

let pass = 0, fail = 0;
const ok = (name, cond) => { cond ? pass++ : fail++; if (!cond) console.log("FAIL " + name); };

globalThis.fetch = async () => { throw new Error("network disabled"); };
AbortSignal.timeout = () => undefined;
const worker = await import(pathToFileURL(path.join(root, "workers", "scan-api", "src", "index.js")).href);

const db = new DatabaseSync(":memory:");
const apply = (p) => { try { db.exec(fs.readFileSync(p, "utf8")); } catch { /* ordering no-ops */ } };
apply(path.join(root, "database", "schema.sql"));
for (const f of fs.readdirSync(path.join(root, "database", "migrations")).filter((f) => f.endsWith(".sql")).sort()) apply(path.join(root, "database", "migrations", f));
db.exec("PRAGMA foreign_keys = OFF");
const makeD1 = (db) => { const wrap = (sql, a) => ({ first: async () => db.prepare(sql).get(...a) ?? null, all: async () => ({ results: db.prepare(sql).all(...a) }), run: async () => { const r = db.prepare(sql).run(...a); return { meta: { changes: r.changes } }; } }); return { prepare(sql) { const b = wrap(sql, []); b.bind = (...a) => wrap(sql, a); return b; } }; };

// ── 1. Unit helpers ──────────────────────────────────────────────────────────
ok("buildTlsRptValue → v=TLSRPTv1; rua=mailto:…", buildTlsRptValue("r1@reports.cybermeters.com") === "v=TLSRPTv1; rua=mailto:r1@reports.cybermeters.com");
ok("customer name for tlsrpt is _smtp._tls.<domain>", hostedCustomerRecordName("acme.co.uk", "tlsrpt") === "_smtp._tls.acme.co.uk");
ok("customer name for dmarc unchanged (_dmarc.)", hostedCustomerRecordName("acme.co.uk", "dmarc") === "_dmarc.acme.co.uk");

// ── Seed: u_a (member of ws_a), ws_b owned by u_other; domain + endpoint ─────
db.prepare("INSERT INTO users (id,email,email_verified) VALUES ('u_a','a@example.co.uk',1)").run();
db.prepare("INSERT INTO workspaces (id,name,owner_user_id) VALUES ('ws_a','Acme','u_a')").run();
db.prepare("INSERT INTO workspaces (id,name,owner_user_id) VALUES ('ws_b','Other','u_other')").run();
db.prepare("INSERT INTO workspace_members (workspace_id,user_id,role) VALUES ('ws_a','u_a','owner')").run();
db.prepare("INSERT INTO domains (id,user_id,domain) VALUES ('d_a','u_a','acme.co.uk')").run();
db.prepare("INSERT INTO workspace_domains (workspace_id,domain_id) VALUES ('ws_a','d_a')").run();
db.prepare("INSERT INTO dmarc_ingest_endpoints (id,workspace_id,domain_id,domain,token_hash,address_local,status,created_at) VALUES ('ep1','ws_a','d_a','acme.co.uk','tok-hash-1','rpt7f3a','active',datetime('now'))").run();

const TOKEN = "tok_a";
db.prepare("INSERT INTO user_sessions (id,user_id,token_hash,expires_at) VALUES ('s_a','u_a',?, datetime('now','+1 day'))").run(await hashToken(TOKEN));

const env = { cybermeters_db: makeD1(db), ALLOWED_ORIGIN: "https://app.cybermeters.com", APP_VERSION: "test", RUA_INBOUND_DOMAIN: "reports.cybermeters.com" };
const ctx = { waitUntil: () => {}, passThroughOnException: () => {} };
const call = async (method, p, token) => {
  const res = await worker.default.fetch(new Request(`https://app.cybermeters.com${p}`, { method, headers: token ? { Authorization: `Bearer ${token}` } : {} }), env, ctx);
  let body = {}; try { body = await res.json(); } catch { /* */ }
  return { status: res.status, body };
};
const BASE = "/api/workspaces/ws_a/domains/acme.co.uk/hosted-tls-rpt";

// ── 2. Create ────────────────────────────────────────────────────────────────
const created = await call("POST", BASE, TOKEN);
ok("create returns 201", created.status === 201);
ok("record is record_type tlsrpt", created.body.record?.record_type === "tlsrpt");
ok("cname_name is _smtp._tls.<domain>", created.body.record?.cname_name === "_smtp._tls.acme.co.uk");
ok("instructions point at _smtp._tls.<domain>", created.body.instructions?.cname_name === "_smtp._tls.acme.co.uk");
ok("value is a TLS-RPT record to our reporting mailbox", /^v=TLSRPTv1; rua=mailto:rpt7f3a@reports\.cybermeters\.com$/.test(created.body.record?.current_value || ""));
ok("no DMARC ramp fields leak onto tlsrpt (autopilot false, no policy_step)", created.body.record?.autopilot === false && created.body.record?.policy_step == null);

// Row persisted with the right kind + stored customer_name.
const row = db.prepare("SELECT * FROM hosted_dns_entries WHERE workspace_id='ws_a' AND domain='acme.co.uk' AND record_kind='tlsrpt'").get();
ok("row persisted record_kind=tlsrpt", !!row && row.record_kind === "tlsrpt");
ok("row customer_name stored", row?.customer_name === "_smtp._tls.acme.co.uk");
ok("row starts pending_dns (no CF creds → not published)", row?.verification_state === "pending_dns");

// ── 3. Idempotent create + GET + verify + coexistence with DMARC ─────────────
ok("second create is a no-op (already_exists)", (await call("POST", BASE, TOKEN)).body.already_exists === true);
const got = await call("GET", BASE, TOKEN);
ok("GET returns the tlsrpt record", got.status === 200 && got.body.record?.record_type === "tlsrpt");
const verified = await call("GET", `${BASE}/verify`, TOKEN);
ok("verify responds 200 (DNS disabled → not connected)", verified.status === 200 && verified.body.record?.status !== "connected");

// A DMARC entry can live on the SAME domain (UNIQUE is per kind).
db.prepare("INSERT INTO hosted_dns_entries (id,workspace_id,domain,record_kind,customer_name,target_name,target_value,verification_state) VALUES ('hd-dmarc1','ws_a','acme.co.uk','dmarc','_dmarc.acme.co.uk','hd-dmarc1.dmarc.cybermeters.com','v=DMARC1; p=none','connected')").run();
ok("DMARC + TLS-RPT coexist on one domain", db.prepare("SELECT COUNT(DISTINCT record_kind) c FROM hosted_dns_entries WHERE domain='acme.co.uk'").get().c === 2);

// ── 4. Delete (grace-protected removal request) ──────────────────────────────
const del = await call("DELETE", BASE, TOKEN);
ok("delete returns 200 + pending_removal", del.status === 200 && del.body.record?.status === "pending_removal");
ok("row moved to pending_removal", db.prepare("SELECT verification_state v FROM hosted_dns_entries WHERE record_kind='tlsrpt'").get().v === "pending_removal");

// ── 5. Tenant isolation ──────────────────────────────────────────────────────
ok("non-member is denied another workspace (403)", (await call("POST", "/api/workspaces/ws_b/domains/acme.co.uk/hosted-tls-rpt", TOKEN)).status === 403);
ok("unauthenticated is rejected (401)", (await call("GET", BASE)).status === 401);

console.log(`\nHosted TLS-RPT: ${pass}/${pass + fail} passed`);
if (fail) { console.error("hosted-tls-rpt validation FAILED"); process.exit(1); }
console.log("hosted-tls-rpt validation passed");
