#!/usr/bin/env node
//
// DMARC aggregate-XML parser safety (internal pentest §18 — locked as regression).
// The RUA ingest parser is a hostile-input surface (attacker-supplied XML arrives
// by email). It must be immune to XXE, external-entity / DTD attacks,
// entity-expansion (billion-laughs) DoS, and oversized-input DoS. The parser is
// regex-based (no XML/DOM engine, so no entity resolver) AND explicitly rejects
// DOCTYPE/ENTITY/stylesheet declarations + caps size (2 MB) and rows (5000). This
// harness proves every one of those defenses so they can never regress.
// Requires Node 24+. CI-blocking.
//
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const { parseDmarcAggregateXml, DMARC_XML_MAX_BYTES, DMARC_MAX_RECORDS } = await import(
  pathToFileURL(path.join(root, "workers", "scan-api", "src", "lib", "dmarc-ingest.js")).href
);

let pass = 0, fail = 0;
const ok = (name, cond) => { cond ? pass++ : fail++; if (!cond) console.log("FAIL " + name); };

const validReport = (records = 1) => {
  const rows = Array.from({ length: records }, (_, i) =>
    `<record><row><source_ip>203.0.113.${i % 256}</source_ip><count>1</count>` +
    `<policy_evaluated><disposition>none</disposition><dkim>pass</dkim><spf>pass</spf></policy_evaluated></row>` +
    `<identifiers><header_from>example.co.uk</header_from></identifiers>` +
    `<auth_results><dkim><domain>example.co.uk</domain><result>pass</result></dkim></auth_results></record>`
  ).join("");
  return `<?xml version="1.0"?><feedback><report_metadata><org_name>Acme</org_name>` +
    `<report_id>r1</report_id></report_metadata><policy_published><domain>example.co.uk</domain>` +
    `<p>none</p></policy_published>${rows}</feedback>`;
};

// ── Positive control: a valid report parses ──────────────────────────────────
const good = parseDmarcAggregateXml(validReport(2));
ok("valid report parses without error", !good.error);
ok("valid report extracts policy domain", good.policy_published?.domain === "example.co.uk");
ok("valid report extracts records", Array.isArray(good.records) && good.records.length === 2);

// ── XXE: classic external-entity file read must be rejected ──────────────────
const xxeFile = `<?xml version="1.0"?><!DOCTYPE feedback [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><feedback><report_metadata><org_name>&xxe;</org_name></report_metadata></feedback>`;
const xxeRes = parseDmarcAggregateXml(xxeFile);
ok("XXE (DOCTYPE + external ENTITY) is rejected as unsafe_xml", xxeRes.error === "unsafe_xml");
ok("XXE output never contains file contents", !JSON.stringify(xxeRes).includes("root:"));

// ── XXE via SSRF (external entity pointing at a URL) ─────────────────────────
const xxeSsrf = `<!DOCTYPE feedback [<!ENTITY x SYSTEM "http://169.254.169.254/latest/meta-data/">]><feedback><report_metadata><org_name>&x;</org_name></report_metadata></feedback>`;
ok("XXE-SSRF (ENTITY → URL) is rejected", parseDmarcAggregateXml(xxeSsrf).error === "unsafe_xml");

// ── Billion-laughs / entity-expansion DoS must be rejected ───────────────────
const billion = `<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;&lol;">]><feedback><report_metadata><org_name>&lol2;</org_name></report_metadata></feedback>`;
ok("billion-laughs entity expansion is rejected", parseDmarcAggregateXml(billion).error === "unsafe_xml");

// ── Other disallowed declarations ────────────────────────────────────────────
ok("xml-stylesheet declaration is rejected", parseDmarcAggregateXml(`<?xml-stylesheet type="text/xsl" href="x"?><feedback></feedback>`).error === "unsafe_xml");
ok("lowercase <!doctype ... > is also rejected (case-insensitive)", parseDmarcAggregateXml(`<!doctype feedback><feedback></feedback>`).error === "unsafe_xml");
ok("bare <!ENTITY without DOCTYPE is rejected", parseDmarcAggregateXml(`<!ENTITY e "x"><feedback></feedback>`).error === "unsafe_xml");

// ── Entities are NEVER resolved: a bare &entity; without a declaration is
//    treated as literal text, not expanded (regex parser has no entity engine).
const literal = parseDmarcAggregateXml(validReport(1).replace("<org_name>Acme</org_name>", "<org_name>&xxe;</org_name>"));
ok("a bare &entity; is left as literal text, never expanded", literal.metadata?.org_name === "&xxe;");

// ── Oversized-input DoS: > 2 MB is rejected before parsing ───────────────────
const huge = `<feedback>${"A".repeat(DMARC_XML_MAX_BYTES + 1024)}</feedback>`;
ok("input over 2 MB is rejected as xml_too_large", parseDmarcAggregateXml(huge).error === "xml_too_large");
ok("size cap constant is 2 MB", DMARC_XML_MAX_BYTES === 2 * 1024 * 1024);

// ── Row-count DoS: record processing is capped at DMARC_MAX_RECORDS ──────────
const many = parseDmarcAggregateXml(validReport(DMARC_MAX_RECORDS + 1000));
ok("record processing is capped (no unbounded rows)", Array.isArray(many.records) && many.records.length <= DMARC_MAX_RECORDS);
ok("row cap constant is 5000", DMARC_MAX_RECORDS === 5000);

// ── Empty / garbage input handled safely ─────────────────────────────────────
ok("empty input → empty_xml (no crash)", parseDmarcAggregateXml("").error === "empty_xml");
ok("non-string input → empty_xml (no crash)", parseDmarcAggregateXml(null).error === "empty_xml");
ok("non-DMARC XML → invalid_structure (no crash)", parseDmarcAggregateXml("<html><body>hi</body></html>").error === "invalid_structure");

console.log(`\nDMARC XML safety: ${pass}/${pass + fail} passed`);
if (fail) { console.error("dmarc-xml-safety validation FAILED"); process.exit(1); }
console.log("dmarc-xml-safety validation passed");
