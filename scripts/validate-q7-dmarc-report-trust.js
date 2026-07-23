#!/usr/bin/env node
//
// Q7 — DMARC / TLS-RPT report trust boundary. CI-blocking. Node 24+.
//
// The rua report address is, by DMARC/TLS-RPT protocol, an UNAUTHENTICATED public
// inbox (customers publish it in DNS). This proves the parser, tenant binding,
// dedupe and inbound-rate-limit boundary. Gate 1's end-to-end downstream
// non-authority proof lives in validate-inbound-email-authority-containment.js.
//
// The former P3 disposition is superseded by the confirmed P0 authority path:
// unauthenticated inbound data could steer external DNS and authoritative
// outcomes. PR-5.5 Gate 1 contains that path without changing ingest semantics.
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const imp = (rel) => import(pathToFileURL(path.join(root, "workers", "scan-api", "src", rel)).href);
const read = (rel) => fs.readFileSync(path.join(root, "workers", "scan-api", "src", rel), "utf8");
const readRepo = (rel) => fs.readFileSync(path.join(root, rel), "utf8");

const { parseDmarcAggregateXml, dmarcReportDomainMatches, ingestDmarcReport } = await imp("lib/dmarc-ingest.js");
const { handleInboundEmail } = await imp("email/inbound.js");

let pass = 0, fail = 0;
const ok = (name, cond) => { cond ? pass++ : fail++; if (!cond) console.log("FAIL " + name); };

const VALID_XML = `<?xml version="1.0"?><feedback>
  <report_metadata><org_name>attacker.example</org_name><email>a@attacker.example</email>
    <report_id>forged-1</report_id><date_range><begin>1</begin><end>2</end></date_range></report_metadata>
  <policy_published><domain>victim.example</domain><p>none</p></policy_published>
  <record><row><source_ip>1.2.3.4</source_ip><count>10</count>
    <policy_evaluated><disposition>none</disposition><dkim>pass</dkim><spf>pass</spf></policy_evaluated></row>
    <identifiers><header_from>victim.example</header_from></identifiers></record>
</feedback>`;

// ── Section A: parser safety (hostile input bounded) ──────────────────────────
ok("A valid DMARC XML parses", !parseDmarcAggregateXml(VALID_XML).error);
ok("A DOCTYPE (XXE) rejected", parseDmarcAggregateXml(`<!DOCTYPE x [<!ENTITY e "y">]>${VALID_XML}`).error === "unsafe_xml");
ok("A ENTITY declaration rejected", parseDmarcAggregateXml(`<!ENTITY e SYSTEM "file:///etc/passwd">${VALID_XML}`).error === "unsafe_xml");
ok("A xml-stylesheet rejected", parseDmarcAggregateXml(`<?xml-stylesheet href="x"?>${VALID_XML}`).error === "unsafe_xml");
ok("A oversized XML rejected", parseDmarcAggregateXml("<feedback>" + "x".repeat(3 * 1024 * 1024) + "</feedback>").error === "xml_too_large");
ok("A empty XML rejected", parseDmarcAggregateXml("").error === "empty_xml");
ok("A non-report structure rejected", parseDmarcAggregateXml("<html><body>hi</body></html>").error === "invalid_structure");
// domain-match gate: a report naming a foreign domain does not match the bound domain
ok("A foreign-domain report fails domain-match", dmarcReportDomainMatches(parseDmarcAggregateXml(VALID_XML), "other.example") === false);
ok("A correct-domain report passes domain-match", dmarcReportDomainMatches(parseDmarcAggregateXml(VALID_XML), "victim.example") === true);

// ── Section B: ingest is workspace/domain-scoped telemetry, no authority ──────
function makeDb({ dedupe = false } = {}) {
  const inserts = { dmarc_aggregate_reports: [], dmarc_aggregate_records: [] };
  const db = {
    inserts,
    prepare(sql) {
      let args = [];
      const isClaimInsert = /INSERT OR IGNORE INTO aggregate_report_ingest_claims/.test(sql);
      const isClaimSelect = /FROM aggregate_report_ingest_claims/.test(sql) &&
        /^\s*SELECT/i.test(sql);
      const insTable = /INSERT INTO dmarc_aggregate_reports/.test(sql) ? "dmarc_aggregate_reports"
                     : /INSERT INTO dmarc_aggregate_records/.test(sql) ? "dmarc_aggregate_records" : null;
      // crude column extraction for the reports insert (to assert workspace_id binding)
      return {
        bind(...a) { args = a; return this; },
        async run() {
          if (insTable) inserts[insTable].push(args);
          return { meta: { changes: isClaimInsert && dedupe ? 0 : 1 } };
        },
        async first() {
          return isClaimSelect && dedupe
            ? { id: "claim_existing", report_id: "existing", content_hash: "",
                ingest_state: "complete", source_scope: "observational" }
            : null;
        },
        async all() { return { results: [] }; },
      };
    },
    async batch(s) { const o = []; for (const x of s) o.push(await x.run()); return o; },
  };
  return db;
}

// correct-domain forged report → ingested as telemetry, bound to the PASSED workspace
{
  const db = makeDb();
  const r = await ingestDmarcReport({ cybermeters_db: db }, { workspaceId: "wsVICTIM", domain: "victim.example",
    source: "inbound_email", xmlString: VALID_XML, enforceDomainMatch: true,
    provenance: { auth_verdict: "unverified", reporter_domain: "attacker.example" } });
  ok("B forged correct-domain report ingested as telemetry", r.ok === true && r.imported === true);
  ok("B report row bound to the endpoint workspace_id (arg[1])", db.inserts.dmarc_aggregate_reports[0]?.[1] === "wsVICTIM");
  ok("B record rows bound to the endpoint workspace_id (arg[2])", db.inserts.dmarc_aggregate_records.every((a) => a[2] === "wsVICTIM"));
  ok("B ingest returns no 'verified'/authority signal", !("verified" in r) && !("score" in r) && !("healthy" in r));
}
// foreign-domain report with enforceDomainMatch → rejected (no cross-domain injection)
{
  const db = makeDb();
  const r = await ingestDmarcReport({ cybermeters_db: db }, { workspaceId: "wsA", domain: "mine.example",
    source: "inbound_email", xmlString: VALID_XML, enforceDomainMatch: true });
  ok("B foreign-domain report rejected (domain_mismatch)", r.ok === false && r.error === "domain_mismatch");
  ok("B rejected report wrote NO report rows", db.inserts.dmarc_aggregate_reports.length === 0);
}
// missing binding → safe rejection
{
  const r = await ingestDmarcReport({ cybermeters_db: makeDb() }, { workspaceId: null, domain: null, xmlString: VALID_XML });
  ok("B missing workspace binding rejected", r.ok === false && r.error === "missing_binding");
}
// dedupe → duplicate is not re-counted
{
  const db = makeDb({ dedupe: true });
  const r = await ingestDmarcReport({ cybermeters_db: db }, { workspaceId: "wsA", domain: "victim.example",
    source: "inbound_email", xmlString: VALID_XML, enforceDomainMatch: true });
  ok("B duplicate report deduped (not re-inserted)", r.ok === true && r.duplicate === true && db.inserts.dmarc_aggregate_reports.length === 0);
}

// ── Section C: per-endpoint inbound rate limit (the added bounded control) ─────
function makeInboundDb() {
  const audits = [];
  const endpoint = { id: "ep1", workspace_id: "wsA", domain: "victim.example", domain_id: "d1",
    address_local: "cmrua_abcd1234", status: "active", is_active: 1 };
  return {
    audits, endpoint,
    prepare(sql) { let args = [];
      const kind = /FROM dmarc_ingest_endpoints/.test(sql) ? "endpoint"
                 : /INSERT INTO audit_events/.test(sql) ? "audit"
                 : /INSERT INTO dmarc_aggregate_reports/.test(sql) ? "ingest" : "other";
      return { bind(...a) { args = a; return this; },
        async run() { if (kind === "audit") audits.push(args); return { meta: { changes: 1 } }; },
        async first() { return kind === "endpoint" ? endpoint : null; }, async all() { return { results: [] }; } };
    },
    async batch(s) { const o = []; for (const x of s) o.push(await x.run()); return o; },
  };
}
function makeMsg() {
  let rawRead = false;
  return { _rawRead: () => rawRead, to: "cmrua_abcd1234@reports.cybermeters.com", rawSize: 100,
    get raw() { rawRead = true; return new ReadableStream({ start(c) { c.enqueue(new Uint8Array([1])); c.close(); } }); } };
}
const env = { RUA_INBOUND_DOMAIN: "reports.cybermeters.com", cybermeters_db: null };
// limiter says OVER LIMIT → audited drop, ingestion never reached
{
  const db = makeInboundDb(); const msg = makeMsg();
  await handleInboundEmail(msg, { ...env, cybermeters_db: db }, {}, {
    consumeApiRateLimit: async () => ({ status: 429 }), rateLimitScopeId: async (p, v) => `${p}_${v}` });
  ok("C over-limit inbound email audited as rate_limited", db.audits.some((a) => a.some((x) => String(x).includes("dmarc_inbound_email_rate_limited") || String(x).includes("rate_limited"))));
  ok("C over-limit inbound email did NOT read the raw body / ingest", msg._rawRead() === false);
}
// limiter fails open (returns null) → processing proceeds (raw body read)
{
  const db = makeInboundDb(); const msg = makeMsg();
  await handleInboundEmail(msg, { ...env, cybermeters_db: db }, {}, {
    consumeApiRateLimit: async () => null, rateLimitScopeId: async (p, v) => `${p}_${v}` });
  ok("C fail-open limiter lets processing proceed", msg._rawRead() === true);
}

// ── Section D: absence-of-authority + self-proving guards ─────────────────────
const ingestSrc  = read("lib/dmarc-ingest.js");
const inboundSrc  = read("email/inbound.js");
function guard(name, src, predicate, mutate) {
  ok(`${name} — holds`, predicate(src) === true);
  const m = mutate(src);
  ok(`${name} — mutation changed source`, m !== src);
  ok(`${name} — CAUGHT when reintroduced`, predicate(m) === false);
}
// tenant binding: the reports INSERT binds workspace_id
guard("D reports INSERT binds workspace_id", ingestSrc,
  (s) => /\(id, workspace_id, domain, org_name/.test(s),
  (s) => s.replace("workspace_id, domain, org_name", "domain, org_name"));
// size cap present
guard("D XML size cap enforced", ingestSrc,
  (s) => /byteLen > DMARC_XML_MAX_BYTES/.test(s),
  (s) => s.replace("byteLen > DMARC_XML_MAX_BYTES", "false"));
// parser safety present
guard("D DOCTYPE/ENTITY parser guard present", ingestSrc,
  (s) => /<!DOCTYPE/.test(s) && /<!ENTITY/.test(s) && /unsafe_xml/.test(s),
  (s) => s.replace(/if \(\/<!DOCTYPE\/i\.test\(xml\)[\s\S]*?return \{ error: "unsafe_xml"[^}]*\};/, ""));
// domain-match gate present (foreign workspace/domain accepted → mutation)
guard("D enforceDomainMatch gate present", ingestSrc,
  (s) => /enforceDomainMatch && !dmarcReportDomainMatches\(parsed, domain\)/.test(s),
  (s) => s.replace("enforceDomainMatch && !dmarcReportDomainMatches(parsed, domain)", "false"));
// inbound rate limit present
guard("D inbound per-endpoint rate limit present", inboundSrc,
  (s) => /inbound_rate_limiter_not_wired/.test(s) &&
    /deps\.consumeApiRateLimit/.test(s) &&
    /"rua_inbound", 120, 3600/.test(s),
  (s) => s.replace('"rua_inbound", 120, 3600', '"rua_inbound", 999999, 3600'));

// Real routed entrypoint wiring: both Workers import the same cycle-safe
// implementation and the standalone export cannot bypass dependency injection.
const apiEntry = read("index.js");
const emailEntry = readRepo("workers/email-ingest/src/index.js");
ok("D API Worker imports the canonical rate limiter",
  /from "\.\/lib\/rate-limit\.js"/.test(apiEntry));
ok("D standalone email Worker imports the same canonical rate limiter",
  /from "\.\.\/\.\.\/scan-api\/src\/lib\/rate-limit\.js"/.test(emailEntry));
guard("D standalone email export injects the mandatory limiter", emailEntry,
  (s) => /handleInboundEmail\(message, env, ctx, \{ consumeApiRateLimit, rateLimitScopeId \}\)/.test(s),
  (s) => s.replace(
    /email:\s*\(message, env, ctx\)\s*=>\s*\n?\s*handleInboundEmail\(message, env, ctx, \{ consumeApiRateLimit, rateLimitScopeId \}\),/,
    "email: handleInboundEmail,",
  ));

// Direct scoring/posture engines still do not read the ingest tables. The
// authority-bearing sender/readiness/lifecycle consumers are separately proven
// source-gated by validate-inbound-email-authority-containment.js.
const SCORING = ["engines/scoring.js", "engines/business-risk.js", "engines/executive-report.js"];
for (const f of SCORING) {
  const src = read(f);
  ok(`D ${f} does not read ingested report tables (no score/health credit)`,
    !/dmarc_aggregate_reports|dmarc_aggregate_records|email_sender_sources|tlsrpt_aggregate/.test(src));
}
// verified-not-trusted: the customer-facing rua-verified derives from the DNS record,
// never from the stored ingest auth_verdict (no SELECT of auth_verdict for a decision).
{
  const prov = read("engines/sender-provenance.js");
  ok("D no decision SELECTs the stored auth_verdict", !/SELECT[^;]*auth_verdict/i.test(prov));
  ok("D rua-verified derives from the DNS record", /cybermetersRuaPresentInDmarcRecord|rua.*dmarc.*record/i.test(prov));
}

console.log(`\nQ7 DMARC/TLS-RPT trust boundary: ${pass}/${pass + fail} passed`);
if (fail) { console.error("q7-dmarc-report-trust validation FAILED"); process.exit(1); }
console.log("q7-dmarc-report-trust validation passed");
