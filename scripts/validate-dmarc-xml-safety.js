#!/usr/bin/env node
//
// DMARC aggregate-XML parser safety (PR-5.5 Gate 4, CI-blocking).
// Hostile XML must remain bounded, non-resolving and structurally unambiguous.
// The mutation checks below make the critical guards executable CI contracts.
//
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const parserPath = path.join(
  root,
  "workers",
  "scan-api",
  "src",
  "lib",
  "dmarc-ingest.js",
);
const {
  DMARC_MAX_MESSAGES_PER_RECORD,
  DMARC_MAX_RECORDS,
  DMARC_XML_MAX_BYTES,
  dmarcReportDomainMatches,
  parseDmarcAggregateXml,
} = await import(pathToFileURL(parserPath).href);

let pass = 0;
let fail = 0;
const ok = (name, condition) => {
  if (condition) pass += 1;
  else {
    fail += 1;
    console.log(`FAIL ${name}`);
  }
};

function record(index = 0, count = "1") {
  const third = Math.floor(index / 250) % 250;
  const fourth = (index % 250) + 1;
  return `<record><row><source_ip>203.0.${third}.${fourth}</source_ip>` +
    `<count>${count}</count><policy_evaluated><disposition>none</disposition>` +
    `<dkim>pass</dkim><spf>pass</spf></policy_evaluated></row>` +
    `<identifiers><header_from>example.co.uk</header_from></identifiers></record>`;
}

function validReport(records = 1) {
  const rows = Array.from({ length: records }, (_, index) => record(index)).join("");
  return `<?xml version="1.0"?><feedback>` +
    `<report_metadata><org_name>Acme</org_name><email>reports@acme.example</email>` +
    `<report_id>r1</report_id><date_range><begin>1784764800</begin>` +
    `<end>1784851200</end></date_range></report_metadata>` +
    `<policy_published><domain>example.co.uk</domain><adkim>r</adkim>` +
    `<aspf>s</aspf><p>none</p><sp>quarantine</sp><pct>100</pct>` +
    `</policy_published>${rows}</feedback>`;
}

const VALID = validReport(2);
const good = parseDmarcAggregateXml(VALID);
ok("valid strict report parses", !good.error);
ok("valid report extracts one policy domain",
  good.policy_published?.domain === "example.co.uk");
ok("valid report extracts bounded records",
  Array.isArray(good.records) && good.records.length === 2);
ok("default namespace on the literal feedback element remains usable",
  !parseDmarcAggregateXml(
    VALID.replace("<feedback>", '<feedback xmlns="urn:ietf:params:xml:ns:dmarc-2.0">'),
  ).error);
ok("lookalike feedback in an unrelated default namespace is rejected",
  parseDmarcAggregateXml(
    VALID.replace("<feedback>", '<feedback xmlns="https://attacker.example/dmarc">'),
  ).error === "unsupported_namespace");

// Existing non-resolving XML controls remain hard gates.
const xxeFile = `<?xml version="1.0"?><!DOCTYPE feedback [` +
  `<!ENTITY xxe SYSTEM "file:///etc/passwd">]>${VALID.replace("Acme", "&xxe;")}`;
const xxeResult = parseDmarcAggregateXml(xxeFile);
ok("DOCTYPE plus external ENTITY is rejected", xxeResult.error === "unsafe_xml");
ok("XXE result cannot contain resolved file content",
  !JSON.stringify(xxeResult).includes("root:"));
ok("URL external entity is rejected",
  parseDmarcAggregateXml(
    `<!DOCTYPE feedback [<!ENTITY x SYSTEM "http://169.254.169.254/">]>${VALID}`,
  ).error === "unsafe_xml");
ok("entity expansion declaration is rejected",
  parseDmarcAggregateXml(
    `<!DOCTYPE feedback [<!ENTITY a "a"><!ENTITY b "&a;&a;">]>${VALID}`,
  ).error === "unsafe_xml");
ok("xml-stylesheet is rejected",
  parseDmarcAggregateXml(`<?xml-stylesheet href="x"?>${VALID}`).error === "unsafe_xml");
ok("case-insensitive doctype is rejected",
  parseDmarcAggregateXml(`<!doctype feedback>${VALID}`).error === "unsafe_xml");
ok("bare ENTITY is rejected",
  parseDmarcAggregateXml(`<!ENTITY e "x">${VALID}`).error === "unsafe_xml");
ok("undeclared entity is rejected rather than treated as trusted text",
  parseDmarcAggregateXml(
    VALID.replace("<org_name>Acme</org_name>", "<org_name>&xxe;</org_name>"),
  ).error === "invalid_text");

// Size and complexity caps fail closed before row persistence.
const huge = `<feedback>${"A".repeat(DMARC_XML_MAX_BYTES + 1)}</feedback>`;
ok("XML over 2 MiB is rejected before parsing",
  parseDmarcAggregateXml(huge).error === "xml_too_large");
ok("XML cap remains exactly 2 MiB", DMARC_XML_MAX_BYTES === 2 * 1024 * 1024);
const tooMany = parseDmarcAggregateXml(validReport(DMARC_MAX_RECORDS + 1));
ok("report above record cap is rejected, never truncated",
  tooMany.error === "too_many_records");
ok("record cap remains 5000", DMARC_MAX_RECORDS === 5000);

// The critical DMARC structures are exactly-one singletons.
ok("document without feedback is rejected",
  parseDmarcAggregateXml(VALID.replace("<feedback>", "").replace("</feedback>", ""))
    .error === "invalid_structure");
ok("nested/duplicate feedback is rejected",
  parseDmarcAggregateXml(
    VALID.replace("</feedback>", `<feedback>${VALID}</feedback></feedback>`),
  ).error === "invalid_structure");
ok("missing report_metadata is rejected",
  parseDmarcAggregateXml(
    VALID.replace(/<report_metadata>[\s\S]*?<\/report_metadata>/, ""),
  ).error === "invalid_structure");
ok("duplicate report_metadata is rejected",
  parseDmarcAggregateXml(
    VALID.replace("</report_metadata>", "</report_metadata><report_metadata>" +
      "<org_name>x</org_name><email>x@y.example</email><report_id>x</report_id>" +
      "<date_range><begin>1</begin><end>2</end></date_range></report_metadata>"),
  ).error === "invalid_structure");
ok("missing policy_published is rejected",
  parseDmarcAggregateXml(
    VALID.replace(/<policy_published>[\s\S]*?<\/policy_published>/, ""),
  ).error === "invalid_structure");
ok("duplicate policy_published is rejected",
  parseDmarcAggregateXml(
    VALID.replace("</policy_published>",
      "</policy_published><policy_published><domain>example.co.uk</domain>" +
      "<p>none</p></policy_published>"),
  ).error === "invalid_structure");
ok("duplicate policy domain is rejected rather than first/last wins",
  parseDmarcAggregateXml(
    VALID.replace("</domain>", "</domain><domain>attacker.example</domain>"),
  ).error === "invalid_structure");
ok("critical metadata nested under a record is rejected",
  parseDmarcAggregateXml(
    VALID.replace(
      /<report_metadata>([\s\S]*?)<\/report_metadata>/,
      "",
    ).replace(
      "<record>",
      `<record><report_metadata><org_name>Acme</org_name>` +
      `<email>reports@acme.example</email><report_id>r1</report_id>` +
      `<date_range><begin>1784764800</begin><end>1784851200</end>` +
      `</date_range></report_metadata>`,
    ),
  ).error === "invalid_structure");

// Namespace prefixes and lookalikes cannot satisfy fixed critical names.
ok("prefixed feedback lookalike is rejected",
  parseDmarcAggregateXml(
    VALID.replace(/feedback/g, "d:feedback"),
  ).error === "unsupported_namespace");
ok("prefixed policy domain lookalike is rejected",
  parseDmarcAggregateXml(
    VALID.replace("<domain>", "<d:domain>").replace("</domain>", "</d:domain>"),
  ).error === "unsupported_namespace");
ok("unprefixed policy_published lookalike is rejected",
  parseDmarcAggregateXml(
    VALID.replace(/policy_published/g, "policy_publishedx"),
  ).error === "invalid_structure");

// Missing/empty policy identity is never attributable.
const missingPolicyDomain = parseDmarcAggregateXml(
  VALID.replace("<domain>example.co.uk</domain>", ""),
);
const emptyPolicyDomain = parseDmarcAggregateXml(
  VALID.replace("<domain>example.co.uk</domain>", "<domain> </domain>"),
);
ok("missing policy domain is rejected", missingPolicyDomain.error === "invalid_structure");
ok("empty policy domain is rejected", emptyPolicyDomain.error === "invalid_structure");
ok("missing policy domain cannot match a bound domain",
  dmarcReportDomainMatches({ policy_published: {} }, "example.co.uk") === false);

// Counts are exact bounded integers: no coercion, rounding, NaN or overflow.
for (const [label, value] of [
  ["negative", "-1"],
  ["decimal", "1.5"],
  ["NaN-like", "NaN"],
  ["over-cap", String(DMARC_MAX_MESSAGES_PER_RECORD + 1)],
]) {
  ok(`${label} record count is rejected`,
    parseDmarcAggregateXml(
      validReport(1).replace("<count>1</count>", `<count>${value}</count>`),
    ).error === "invalid_record_count");
}
ok("zero record count is accepted as a bounded integer",
  !parseDmarcAggregateXml(
    validReport(1).replace("<count>1</count>", "<count>0</count>"),
  ).error);

// Vocabulary, date, domain, IP and text bounds.
ok("unknown disposition is rejected",
  parseDmarcAggregateXml(
    VALID.replace("<disposition>none</disposition>", "<disposition>allow</disposition>"),
  ).error === "invalid_enum");
ok("reversed date range is rejected",
  parseDmarcAggregateXml(
    VALID.replace("<begin>1784764800</begin>", "<begin>1784851201</begin>"),
  ).error === "invalid_date_range");
ok("invalid policy domain is rejected",
  parseDmarcAggregateXml(
    VALID.replace("<domain>example.co.uk</domain>", "<domain>-bad.example</domain>"),
  ).error === "invalid_domain");
ok("invalid source IP is rejected",
  parseDmarcAggregateXml(
    VALID.replace("<source_ip>203.0.0.1</source_ip>",
      "<source_ip>999.0.0.1</source_ip>"),
  ).error === "invalid_source_ip");
ok("overlong report id is rejected",
  parseDmarcAggregateXml(
    VALID.replace("<report_id>r1</report_id>",
      `<report_id>${"r".repeat(257)}</report_id>`),
  ).error === "invalid_text");

ok("empty input is handled without throwing",
  parseDmarcAggregateXml("").error === "empty_xml");
ok("non-string input is handled without throwing",
  parseDmarcAggregateXml(null).error === "empty_xml");
ok("non-DMARC XML is rejected",
  parseDmarcAggregateXml("<html><body>hi</body></html>").error ===
    "invalid_structure");

// Mutation-backed source contracts. If any mutation survives these predicates,
// the validator itself is not protecting the hard gate.
const source = fs.readFileSync(parserPath, "utf8");
function mutationGuard(name, predicate, mutate) {
  ok(`${name} — invariant present`, predicate(source));
  const mutated = mutate(source);
  ok(`${name} — mutation changed source`, mutated !== source);
  ok(`${name} — mutation is killed`, !predicate(mutated));
}

mutationGuard(
  "DOCTYPE/ENTITY rejection",
  (text) => /\/<!DOCTYPE\/i\.test\(xml\)/.test(text) &&
    /\/<!ENTITY\/i\.test\(xml\)/.test(text) &&
    /error: "unsafe_xml"/.test(text),
  (text) => text.replace(
    'if (/<!DOCTYPE/i.test(xml) || /<!ENTITY/i.test(xml) || /<\\?xml-stylesheet/i.test(xml)) {',
    "if (false) {",
  ),
);
mutationGuard(
  "missing policy domain fails closed",
  (text) => /if \(!reportDomain\) return false;/.test(text),
  (text) => text.replace("if (!reportDomain) return false;", "if (!reportDomain) return true;"),
);
mutationGuard(
  "negative and coercible counts rejected",
  (text) => text.includes('if (!/^(?:0|[1-9]\\d*)$/.test(text)) {') &&
    /value < min \|\| value > max/.test(text),
  (text) => text.replace(
    'if (!/^(?:0|[1-9]\\d*)$/.test(text)) {',
    "if (false) {",
  ),
);

console.log(`\nDMARC XML safety: ${pass}/${pass + fail} passed`);
if (fail) {
  console.error("dmarc-xml-safety validation FAILED");
  process.exit(1);
}
console.log("dmarc-xml-safety validation passed");
