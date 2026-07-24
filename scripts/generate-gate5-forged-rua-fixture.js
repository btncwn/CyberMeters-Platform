#!/usr/bin/env node
//
// Generates, but NEVER sends, one strict-schema DMARC RUA XML attachment for
// the founder-executed Gate 5 non-authority test. Use separate `fail` and `pass`
// fixtures to exercise the values that formerly steered rollback and advance.
//
import fs from "node:fs";
import path from "node:path";

const argv = process.argv.slice(2);
const valueOf = (name) => {
  const index = argv.indexOf(name);
  return index >= 0 ? argv[index + 1] : null;
};
const domain = String(valueOf("--domain") || "")
  .trim()
  .toLowerCase()
  .replace(/\.$/, "");
const scenario = String(valueOf("--scenario") || "").trim().toLowerCase();
const outputArg = valueOf("--output");
const suppliedReportId = valueOf("--report-id");

if (!domain || !/^[a-z0-9.-]+$/.test(domain) ||
    !["pass", "fail"].includes(scenario) || !outputArg) {
  console.error(
    "Usage: node scripts/generate-gate5-forged-rua-fixture.js " +
    "--domain example.com --scenario pass|fail --output /absolute/path/report.xml " +
    "[--report-id unique-id]",
  );
  process.exit(64);
}

const outputPath = path.resolve(outputArg);
if (fs.existsSync(outputPath)) {
  console.error(`Refusing to overwrite existing file: ${outputPath}`);
  process.exit(73);
}

const now = Math.floor(Date.now() / 1000);
const reportId = suppliedReportId ||
  `gate5-forged-${scenario}-${domain}-${now}`;
if (!/^[A-Za-z0-9._:@+-]{1,200}$/.test(reportId)) {
  console.error("report-id must be 1-200 safe identifier characters");
  process.exit(64);
}

const passed = scenario === "pass";
const disposition = passed ? "none" : "reject";
const aligned = passed ? "pass" : "fail";
const sourceIp = passed ? "203.0.113.41" : "203.0.113.42";
const count = passed ? 999999 : 999998;
const xml = `<?xml version="1.0" encoding="UTF-8"?>
<feedback>
  <version>1.0</version>
  <report_metadata>
    <org_name>Founder Gate 5 forged non-authority test</org_name>
    <email>founder-controlled@example.invalid</email>
    <report_id>${reportId}</report_id>
    <date_range>
      <begin>${now - 86400}</begin>
      <end>${now}</end>
    </date_range>
  </report_metadata>
  <policy_published>
    <domain>${domain}</domain>
    <adkim>r</adkim>
    <aspf>r</aspf>
    <p>reject</p>
    <sp>reject</sp>
    <pct>100</pct>
  </policy_published>
  <record>
    <row>
      <source_ip>${sourceIp}</source_ip>
      <count>${count}</count>
      <policy_evaluated>
        <disposition>${disposition}</disposition>
        <dkim>${aligned}</dkim>
        <spf>${aligned}</spf>
      </policy_evaluated>
    </row>
    <identifiers>
      <envelope_from>${domain}</envelope_from>
      <header_from>${domain}</header_from>
    </identifiers>
    <auth_results>
      <dkim>
        <domain>${domain}</domain>
        <selector>gate5</selector>
        <result>${aligned}</result>
      </dkim>
      <spf>
        <domain>${domain}</domain>
        <result>${aligned}</result>
      </spf>
    </auth_results>
  </record>
</feedback>
`;

fs.writeFileSync(outputPath, xml, {
  encoding: "utf8",
  flag: "wx",
  mode: 0o600,
});
process.stdout.write(`${JSON.stringify({
  schema: "cybermeters.gate5-forged-rua-fixture/v1",
  sent: false,
  domain,
  scenario,
  report_id: reportId,
  attacker_chosen_message_count: count,
  output: outputPath,
}, null, 2)}\n`);
