#!/usr/bin/env node
//
// TLS-RPT ingestion regression (Phase C). Proves the JSON reports that arrive at
// reports.cybermeters.com are parsed, stored, deduped and attributed correctly —
// via a SEPARATE parser (never the DMARC XML path) — and that the inbound handler
// ROUTES by attachment type: a TLS-RPT attachment reaches TLS-RPT ingest end to
// end (MIME → gunzip → parse → store), and a DMARC XML attachment is NOT picked
// up by the TLS-RPT selector (falls through to the unchanged DMARC path). Plus
// dedup, domain-match, provenance, the read endpoint and tenant isolation.
// Node 24+. CI-blocking.
//
import fs from "node:fs";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const ing = await import(pathToFileURL(path.join(root, "workers", "scan-api", "src", "lib", "tlsrpt-ingest.js")).href);
const { hashToken } = await import(pathToFileURL(path.join(root, "workers", "scan-api", "src", "lib", "auth-crypto.js")).href);
const { parseTlsRptReport, ingestTlsRptReport } = ing;

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
const env = { cybermeters_db: makeD1(db), ALLOWED_ORIGIN: "https://app.cybermeters.com", APP_VERSION: "test", RUA_INBOUND_DOMAIN: "reports.cybermeters.com" };
const ctx = { waitUntil: () => {}, passThroughOnException: () => {} };

const report = (id, { policyDomain = "acme.co.uk", succ = 100, fail = 3, failures = [] } = {}) => JSON.stringify({
  "organization-name": "Google Inc.", "date-range": { "start-datetime": "2026-07-11T00:00:00Z", "end-datetime": "2026-07-11T23:59:59Z" },
  "contact-info": "smtp-tls-reporting@google.com", "report-id": id,
  policies: [{ policy: { "policy-type": "sts", "policy-domain": policyDomain },
    summary: { "total-successful-session-count": succ, "total-failure-session-count": fail },
    "failure-details": failures }],
});

// ── 1. Parser ────────────────────────────────────────────────────────────────
ok("parses a valid report", parseTlsRptReport(report("r1")).ok === true);
ok("rejects malformed JSON", parseTlsRptReport("{not json").ok === false);
ok("rejects a non-object", parseTlsRptReport("[]").ok === false);
ok("rejects a report with no report-id", parseTlsRptReport(JSON.stringify({ policies: [] })).ok === false);
ok("rejects an oversized body", parseTlsRptReport('{"report-id":"x","z":"' + "A".repeat(2 * 1024 * 1024) + '"}').ok === false);
{
  const p = parseTlsRptReport(report("r2", { succ: 90, fail: 10, failures: [
    { "result-type": "certificate-expired", "sending-mta-ip": "1.2.3.4", "receiving-mx-hostname": "mx.acme.co.uk", "failed-session-count": 7 },
    { "result-type": "starttls-not-supported", "failed-session-count": 3 }] }));
  ok("extracts totals + policy", p.report.total_successful_sessions === 90 && p.report.total_failure_sessions === 10 && p.report.primary_policy_type === "sts");
  ok("extracts failure details (bounded)", p.report.failure_count === 2 && p.report.policies[0].failures[0].result_type === "certificate-expired");
}

// ── Seed workspace/domain/endpoint/session ───────────────────────────────────
db.prepare("INSERT INTO users (id,email,email_verified) VALUES ('u_a','a@example.co.uk',1)").run();
db.prepare("INSERT INTO workspaces (id,name,owner_user_id) VALUES ('ws_a','Acme','u_a')").run();
db.prepare("INSERT INTO workspaces (id,name,owner_user_id) VALUES ('ws_b','Other','u_other')").run();
db.prepare("INSERT INTO workspace_members (workspace_id,user_id,role) VALUES ('ws_a','u_a','owner')").run();
db.prepare("INSERT INTO domains (id,user_id,domain) VALUES ('d_a','u_a','acme.co.uk')").run();
db.prepare("INSERT INTO workspace_domains (workspace_id,domain_id) VALUES ('ws_a','d_a')").run();
db.prepare("INSERT INTO dmarc_ingest_endpoints (id,workspace_id,domain_id,domain,token_hash,address_local,status,created_at) VALUES ('ep1','ws_a','d_a','acme.co.uk','th1','cmrua_a1b2c3d4','active',datetime('now'))").run();
const TOKEN = "tok_a";
db.prepare("INSERT INTO user_sessions (id,user_id,token_hash,expires_at) VALUES ('s_a','u_a',?, datetime('now','+1 day'))").run(await hashToken(TOKEN));

// ── 2. Direct ingest: store / dedup / domain-match / provenance ──────────────
const r1 = await ingestTlsRptReport(env, { workspaceId: "ws_a", domain: "acme.co.uk", jsonString: report("rep-100"), enforceDomainMatch: true, provenance: { auth_verdict: "verified" } });
ok("ingest stores a report", r1.ok && r1.duplicate === false && r1.sessions === 103);
ok("report row persisted", db.prepare("SELECT COUNT(*) c FROM tlsrpt_aggregate_reports WHERE workspace_id='ws_a'").get().c === 1);
ok("provenance recorded verified", db.prepare("SELECT provenance p FROM tlsrpt_aggregate_reports WHERE external_report_id='rep-100'").get().p === "verified");
const r1b = await ingestTlsRptReport(env, { workspaceId: "ws_a", domain: "acme.co.uk", jsonString: report("rep-100"), enforceDomainMatch: true });
ok("duplicate report is a no-op (dedup by report-id)", r1b.ok && r1b.duplicate === true && db.prepare("SELECT COUNT(*) c FROM tlsrpt_aggregate_reports").get().c === 1);
const rMis = await ingestTlsRptReport(env, { workspaceId: "ws_a", domain: "acme.co.uk", jsonString: report("rep-x", { policyDomain: "evil.example" }), enforceDomainMatch: true });
ok("domain-mismatch report is rejected", rMis.ok === false && rMis.error === "domain_mismatch");
{
  const withFails = report("rep-f", { failures: [{ "result-type": "validation-failure", "failed-session-count": 4 }] });
  await ingestTlsRptReport(env, { workspaceId: "ws_a", domain: "acme.co.uk", jsonString: withFails, enforceDomainMatch: true, provenance: { auth_verdict: "unverified" } });
  ok("failure detail rows stored", db.prepare("SELECT COUNT(*) c FROM tlsrpt_failure_details WHERE workspace_id='ws_a' AND result_type='validation-failure'").get().c === 1);
  ok("untrusted header-From → provenance unverified", db.prepare("SELECT provenance p FROM tlsrpt_aggregate_reports WHERE external_report_id='rep-f'").get().p === "unverified");
}

// ── 3. Inbound routing via the real email handler ────────────────────────────
const gzip = async (u8) => new Uint8Array(await new Response(new Response(u8).body.pipeThrough(new CompressionStream("gzip"))).arrayBuffer());
const streamOf = (u8) => new Response(u8).body;
const mimeEmail = (b64, ctype, filename) => new TextEncoder().encode([
  "To: cmrua_a1b2c3d4@reports.cybermeters.com", "From: reporter@google.com",
  'Content-Type: multipart/mixed; boundary="BOUND"', "", "--BOUND",
  `Content-Type: ${ctype}`, "Content-Transfer-Encoding: base64",
  `Content-Disposition: attachment; filename="${filename}"`, "", b64, "--BOUND--", "",
].join("\r\n"));
const emailMsg = (bytes) => ({ to: "cmrua_a1b2c3d4@reports.cybermeters.com", rawSize: bytes.length, raw: streamOf(bytes), headers: new Map() });

// TLS-RPT gzip attachment → must land in tlsrpt_aggregate_reports.
const tlsGz = await gzip(new TextEncoder().encode(report("inbound-tls-1")));
const tlsB64 = Buffer.from(tlsGz).toString("base64");
await worker.default.email(emailMsg(mimeEmail(tlsB64, "application/tlsrpt+gzip", "report.json.gz")), env, ctx);
ok("inbound TLS-RPT report routed + stored", db.prepare("SELECT COUNT(*) c FROM tlsrpt_aggregate_reports WHERE external_report_id='inbound-tls-1'").get().c === 1);

// A DMARC .xml attachment must NOT create a tlsrpt row (routes to DMARC path).
const beforeTls = db.prepare("SELECT COUNT(*) c FROM tlsrpt_aggregate_reports").get().c;
const dmarcXml = new TextEncoder().encode("<?xml version=\"1.0\"?><feedback><report_metadata><report_id>d1</report_id></report_metadata></feedback>");
await worker.default.email(emailMsg(mimeEmail(Buffer.from(dmarcXml).toString("base64"), "application/xml", "dmarc.xml")), env, ctx);
ok("DMARC xml attachment does NOT create a tlsrpt row (routing separation)", db.prepare("SELECT COUNT(*) c FROM tlsrpt_aggregate_reports").get().c === beforeTls);

// ── 4. Read endpoint + isolation ─────────────────────────────────────────────
const call = async (p, token) => { const res = await worker.default.fetch(new Request(`https://app.cybermeters.com${p}`, { headers: token ? { Authorization: `Bearer ${token}` } : {} }), env, ctx); let b = {}; try { b = await res.json(); } catch { /* */ } return { status: res.status, body: b }; };
const rep = await call("/api/workspaces/ws_a/domains/acme.co.uk/tls-rpt/reports", TOKEN);
ok("read endpoint returns a summary", rep.status === 200 && rep.body.summary && typeof rep.body.summary.success_rate === "number");
ok("summary counts the ingested reports", rep.body.summary.report_count >= 3);
ok("non-member is denied (403)", (await call("/api/workspaces/ws_b/domains/acme.co.uk/tls-rpt/reports", TOKEN)).status === 403);
ok("unauthenticated is rejected (401)", (await call("/api/workspaces/ws_a/domains/acme.co.uk/tls-rpt/reports")).status === 401);

// ── 5. Deletion completeness ─────────────────────────────────────────────────
ok("tlsrpt tables are in WORKSPACE_PURGE_TABLES", worker.WORKSPACE_PURGE_TABLES.includes("tlsrpt_aggregate_reports") && worker.WORKSPACE_PURGE_TABLES.includes("tlsrpt_failure_details"));

console.log(`\nTLS-RPT ingestion: ${pass}/${pass + fail} passed`);
if (fail) { console.error("tlsrpt-ingest validation FAILED"); process.exit(1); }
console.log("tlsrpt-ingest validation passed");
