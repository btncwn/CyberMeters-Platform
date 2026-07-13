#!/usr/bin/env node
//
// Automated DMARC sender-classification regression.
// Proves the pure classifier taxonomy, ingest-time auto recomputation,
// per-method alignment rollups, provider-map stamping, manual-wins persistence,
// and workspace isolation. Node 24+.
//
import fs from "node:fs";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const workerPath = path.join(root, "workers", "scan-api", "src", "index.js");
const classifier = await import(pathToFileURL(path.join(root, "workers", "scan-api", "src", "engines", "sender-classification.js")).href);
const dmarc = await import(pathToFileURL(path.join(root, "workers", "scan-api", "src", "lib", "dmarc-ingest.js")).href);
const { hashToken } = await import(pathToFileURL(path.join(root, "workers", "scan-api", "src", "lib", "auth-crypto.js")).href);
const { classifySender, PROVIDER_MAP_VERSION } = classifier;
const { ingestDmarcReport } = dmarc;

let pass = 0, fail = 0;
const ok = (name, cond) => { cond ? pass++ : fail++; if (!cond) console.log("FAIL " + name); };

function buildDb() {
  const db = new DatabaseSync(":memory:");
  const apply = (p) => { try { db.exec(fs.readFileSync(p, "utf8")); } catch { /* ordering no-ops */ } };
  apply(path.join(root, "database", "schema.sql"));
  for (const f of fs.readdirSync(path.join(root, "database", "migrations")).filter((f) => f.endsWith(".sql")).sort()) {
    apply(path.join(root, "database", "migrations", f));
  }
  db.exec("PRAGMA foreign_keys = OFF");
  return db;
}

function makeD1(db) {
  const wrap = (sql, args) => ({
    first: async () => db.prepare(sql).get(...args) ?? null,
    all: async () => ({ results: db.prepare(sql).all(...args), success: true, meta: {} }),
    run: async () => { const r = db.prepare(sql).run(...args); return { success: true, meta: { changes: r.changes } }; },
  });
  return { prepare(sql) { const b = wrap(sql, []); b.bind = (...args) => wrap(sql, args); return b; } };
}

function makeEnv(db) {
  return {
    cybermeters_db: makeD1(db),
    ALLOWED_ORIGIN: "https://app.cybermeters.com",
    FRONTEND_URL: "https://app.cybermeters.com",
    APP_VERSION: "test",
  };
}

function reportXml({ id, domain = "acme.co.uk", sourceIp = "203.0.113.10", count = 10,
  spfAligned = "pass", dkimAligned = "pass", spfDomain = "acme.co.uk",
  dkimDomain = "acme.co.uk", headerFrom = "acme.co.uk", spfResult = "pass",
  dkimResult = "pass", disposition = "none" } = {}) {
  return `<?xml version="1.0"?><feedback>` +
    `<report_metadata><org_name>Unit Test</org_name><email>reports@example.net</email><report_id>${id}</report_id>` +
    `<date_range><begin>1783900000</begin><end>1783986400</end></date_range></report_metadata>` +
    `<policy_published><domain>${domain}</domain><p>none</p></policy_published>` +
    `<record><row><source_ip>${sourceIp}</source_ip><count>${count}</count><policy_evaluated>` +
    `<disposition>${disposition}</disposition><dkim>${dkimAligned}</dkim><spf>${spfAligned}</spf>` +
    `</policy_evaluated></row><identifiers><header_from>${headerFrom}</header_from><envelope_from>${spfDomain}</envelope_from></identifiers>` +
    `<auth_results><dkim><domain>${dkimDomain}</domain><selector>s1</selector><result>${dkimResult}</result></dkim>` +
    `<spf><domain>${spfDomain}</domain><result>${spfResult}</result></spf></auth_results></record></feedback>`;
}

// ── 1. Pure classifier taxonomy ──────────────────────────────────────────────
const base = { protected_domain: "acme.co.uk", header_from: "acme.co.uk" };
ok("taxonomy authorised", classifySender({ ...base, total_messages: 100, spf_aligned_messages: 99, dkim_aligned_messages: 100, aligned_messages: 100, failed_messages: 0, provider_guess: "microsoft", provider_confidence: "medium" }).classification === "authorised");
ok("taxonomy likely_authorised", classifySender({ ...base, total_messages: 100, spf_aligned_messages: 99, dkim_aligned_messages: 10, aligned_messages: 99, failed_messages: 1, provider_guess: "google", provider_confidence: "medium" }).classification === "likely_authorised");
ok("taxonomy forwarder", classifySender({ ...base, total_messages: 100, spf_aligned_messages: 0, dkim_aligned_messages: 99, aligned_messages: 99, failed_messages: 1, provider_guess: "unknown" }).classification === "forwarder");
ok("taxonomy mailing_list", classifySender({ ...base, total_messages: 100, spf_aligned_messages: 25, dkim_aligned_messages: 0, aligned_messages: 25, failed_messages: 75, provider_guess: "mailchimp" }).classification === "mailing_list");
ok("taxonomy misconfigured", classifySender({ ...base, total_messages: 100, spf_aligned_messages: 20, dkim_aligned_messages: 10, aligned_messages: 30, failed_messages: 70, provider_guess: "microsoft" }).classification === "misconfigured");
ok("taxonomy unknown low volume", classifySender({ ...base, total_messages: 2, spf_aligned_messages: 2, dkim_aligned_messages: 2, aligned_messages: 2, failed_messages: 0, provider_guess: "microsoft" }).classification === "unknown");
ok("taxonomy suspicious", classifySender({ protected_domain: "acme.co.uk", header_from: "other.example", total_messages: 30, spf_aligned_messages: 0, dkim_aligned_messages: 0, aligned_messages: 0, failed_messages: 30, provider_guess: "unknown" }).classification === "suspicious");
ok("taxonomy unauthorised", classifySender({ ...base, total_messages: 100, spf_aligned_messages: 0, dkim_aligned_messages: 0, aligned_messages: 0, failed_messages: 100, provider_guess: "unknown" }).classification === "unauthorised");
ok("classifier is explainable", classifySender({ ...base, total_messages: 100, spf_aligned_messages: 99, dkim_aligned_messages: 100, aligned_messages: 100, failed_messages: 0, provider_guess: "microsoft" }).reasons.length >= 2);

// ── 2. Real ingest + API path ────────────────────────────────────────────────
globalThis.fetch = async () => { throw new Error("network disabled"); };
AbortSignal.timeout = () => undefined;
const worker = await import(pathToFileURL(workerPath).href);
const db = buildDb();
const env = makeEnv(db);
const ctx = { waitUntil: () => {}, passThroughOnException: () => {} };

db.prepare("INSERT INTO users (id,email,email_verified) VALUES ('u_a','a@example.co.uk',1),('u_b','b@example.co.uk',1)").run();
db.prepare("INSERT INTO workspaces (id,name,owner_user_id) VALUES ('ws_a','Acme','u_a'),('ws_b','Other','u_b')").run();
db.prepare("INSERT INTO workspace_members (workspace_id,user_id,role) VALUES ('ws_a','u_a','owner'),('ws_b','u_b','owner')").run();
db.prepare("INSERT INTO domains (id,user_id,domain) VALUES ('d_a','u_a','acme.co.uk'),('d_b','u_b','other.co.uk')").run();
db.prepare("INSERT INTO workspace_domains (workspace_id,domain_id) VALUES ('ws_a','d_a'),('ws_b','d_b')").run();
db.prepare("INSERT INTO user_sessions (id,user_id,token_hash,expires_at) VALUES ('s_a','u_a',?, datetime('now','+1 day')),('s_b','u_b',?, datetime('now','+1 day'))")
  .run(await hashToken("tok_a"), await hashToken("tok_b"));

const imported = await ingestDmarcReport(env, {
  workspaceId: "ws_a",
  domain: "acme.co.uk",
  source: "manual_paste",
  xmlString: reportXml({
    id: "r1",
    sourceIp: "203.0.113.20",
    count: 10,
    spfAligned: "pass",
    dkimAligned: "fail",
    spfDomain: "spf.protection.outlook.com",
    dkimDomain: "example.invalid",
    headerFrom: "acme.co.uk",
  }),
});
ok("ingest succeeds", imported.ok === true && imported.sourcesUpdated === 1);
let sender = db.prepare("SELECT * FROM email_sender_sources WHERE workspace_id='ws_a' AND domain='acme.co.uk' AND source_ip='203.0.113.20'").get();
ok("per-method SPF count recorded", sender.spf_aligned_messages === 10);
ok("per-method DKIM count recorded", sender.dkim_aligned_messages === 0);
ok("provider map version stamped", sender.provider_map_version === PROVIDER_MAP_VERSION);
ok("auto classification recomputed on ingest", sender.auto_classification === "likely_authorised");
ok("auto reasons stored as JSON", JSON.parse(sender.auto_reasons).length > 0);

const call = async (method, p, token, body = null) => {
  const res = await worker.default.fetch(new Request(`https://app.cybermeters.com${p}`, {
    method,
    headers: { ...(token ? { Authorization: `Bearer ${token}` } : {}), ...(body ? { "Content-Type": "application/json" } : {}) },
    body: body ? JSON.stringify(body) : undefined,
  }), env, ctx);
  let json = {}; try { json = await res.json(); } catch { /* */ }
  return { status: res.status, body: json };
};

let listed = await call("GET", "/api/workspaces/ws_a/domains/acme.co.uk/email-senders", "tok_a");
ok("sender API exposes auto classification", listed.body.senders?.[0]?.auto_classification === "likely_authorised");
ok("sender API exposes auto confidence", typeof listed.body.senders?.[0]?.auto_confidence === "number");
ok("sender API source is auto before manual override", listed.body.senders?.[0]?.classification_source === "auto");
ok("sender API exposes SPF/DKIM rates", listed.body.senders?.[0]?.spf_aligned_rate === 100 && listed.body.senders?.[0]?.dkim_aligned_rate === 0);

const manual = await call("POST", `/api/workspaces/ws_a/domains/acme.co.uk/email-senders/${sender.id}/classify`, "tok_a", {
  classification: "trusted",
  notes: "Confirmed Microsoft 365",
});
ok("manual override endpoint succeeds", manual.status === 200);
ok("manual override stamps classified_at", manual.body.sender?.classified_at != null);
ok("manual override wins effective classification", manual.body.sender?.classification_source === "manual" && manual.body.sender?.effective_classification === "trusted");

const reimported = await ingestDmarcReport(env, {
  workspaceId: "ws_a",
  domain: "acme.co.uk",
  source: "manual_paste",
  xmlString: reportXml({
    id: "r2",
    sourceIp: "203.0.113.20",
    count: 20,
    spfAligned: "fail",
    dkimAligned: "fail",
    spfDomain: "bad.example",
    dkimDomain: "bad.example",
    headerFrom: "acme.co.uk",
  }),
});
ok("re-ingest succeeds", reimported.ok === true);
sender = db.prepare("SELECT * FROM email_sender_sources WHERE id=?").get(sender.id);
ok("manual classification preserved across re-ingest", sender.classification === "trusted" && sender.notes === "Confirmed Microsoft 365" && sender.classified_at != null);
ok("auto fields still recompute after re-ingest", sender.auto_classification && sender.auto_reasons);
ok("per-method counts increment across re-ingest", sender.total_messages === 30 && sender.spf_aligned_messages === 10 && sender.dkim_aligned_messages === 0);
listed = await call("GET", "/api/workspaces/ws_a/domains/acme.co.uk/email-senders", "tok_a");
ok("manual still wins API after auto recompute", listed.body.senders?.[0]?.classification_source === "manual" && listed.body.senders?.[0]?.effective_classification === "trusted");

await ingestDmarcReport(env, {
  workspaceId: "ws_b",
  domain: "other.co.uk",
  source: "manual_paste",
  xmlString: reportXml({ id: "r3", domain: "other.co.uk", sourceIp: "203.0.113.20", headerFrom: "other.co.uk" }),
});
const foreign = await call("GET", "/api/workspaces/ws_a/domains/acme.co.uk/email-senders", "tok_b");
ok("foreign workspace cannot read sender inventory", foreign.status === 403);
ok("tenant rows stay separate for same source IP", db.prepare("SELECT COUNT(*) c FROM email_sender_sources WHERE source_ip='203.0.113.20'").get().c === 2);
ok("tenant auto classifications are scoped", db.prepare("SELECT COUNT(*) c FROM email_sender_sources WHERE workspace_id='ws_b' AND domain='other.co.uk' AND auto_classification IS NOT NULL").get().c === 1);

console.log(`\nSender classification: ${pass}/${pass + fail} passed`);
if (fail) { console.error("sender-classification validation FAILED"); process.exit(1); }
console.log("sender-classification validation passed");
