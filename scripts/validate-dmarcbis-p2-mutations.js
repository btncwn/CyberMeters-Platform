#!/usr/bin/env node
// Item 7 P2 load-bearing mutation proof.
//
// Mutants are temporary adjacent module copies so the real dependency graph is
// retained. Each reintroduced defect must be observable by the corresponding
// P2 contract fixture.
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

import { parseDmarcbisPolicyRecord } from "../workers/scan-api/src/engines/dmarcbis-parser.js";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const engines = path.join(root, "workers/scan-api/src/engines");
const lib = path.join(root, "workers/scan-api/src/lib");
let pass = 0;
let fail = 0;
let sequence = 0;

const ok = (name, condition, detail = "") => {
  condition ? pass += 1 : fail += 1;
  if (condition) console.log(`ok - ${name}`);
  else console.error(`not ok - ${name}${detail ? `: ${detail}` : ""}`);
};

async function withMutant(directory, file, from, to, run) {
  const sourcePath = path.join(directory, file);
  const source = fs.readFileSync(sourcePath, "utf8");
  const mutated = source.replace(from, to);
  ok(`${file} mutation applied`, mutated !== source);
  if (mutated === source) return;
  const mutantPath = path.join(
    directory,
    `.${file.replace(/\.js$/, "")}.p2-mutant.${process.pid}.${++sequence}.js`,
  );
  fs.writeFileSync(mutantPath, mutated);
  try {
    const module = await import(
      `${pathToFileURL(mutantPath).href}?mutation=${sequence}`
    );
    await run(module);
  } finally {
    fs.rmSync(mutantPath, { force: true });
  }
}

await withMutant(
  engines,
  "dmarcbis-production.js",
  "export const DMARCBIS_CORE_BUDGET_MS = 750;",
  "export const DMARCBIS_CORE_BUDGET_MS = 15_000;",
  async (mutant) => {
    ok("MUTANT 15-second DMARC phase makes the R1 allocation fixture red",
      mutant.DMARCBIS_CORE_BUDGET_MS > 750);
  },
);

await withMutant(
  engines,
  "dmarcbis-production.js",
  `result.rua_authorisation_completeness === "not_applicable"
        ? "not_applicable"
        : "incomplete"`,
  `result.rua_authorisation_completeness === "not_applicable"
        ? "not_applicable"
        : "complete"`,
  async (mutant) => {
    const record = parseDmarcbisPolicyRecord(
      "v=DMARC1; p=reject; rua=mailto:agg@reports.vendor.test",
    );
    const refused = await mutant.budgetRefusedDmarcbisExternal({
      policy_source_domain: "example.test",
      organisational_domain: "example.test",
      rua_destinations: record.rua,
    }, "subrequest_budget");
    ok("MUTANT refusal-as-complete makes the no-false-healthy fixture red",
      refused.rua_authorisation_completeness === "complete");
  },
);

await withMutant(
  engines,
  "scan-budget.js",
  `String(resolver || "cloudflare").toLowerCase(),
    String(name || "")`,
  `"resolver-collapsed",
    String(name || "")`,
  async (mutant) => {
    const cloudflare = mutant.dnsCacheKey(
      "_dmarc.example.test",
      "TXT",
      "cloudflare",
    );
    const google = mutant.dnsCacheKey(
      "_dmarc.example.test",
      "TXT",
      "google",
    );
    ok("MUTANT collapsed resolver cache key makes isolation fixture red",
      cloudflare === google);
  },
);

await withMutant(
  engines,
  "email-protection-lifecycle.js",
  "return `dmarc:${domain_id}:${type}:${digest}`;",
  "return `dmarc:${domain_id}:weak:${digest}`;",
  async (mutant) => {
    const weak = await mutant.dmarcPolicyConditionRecordId({
      domain_id: "dom-a",
      condition_type: "weak",
      subject_key: "example.test",
    });
    const missing = await mutant.dmarcPolicyConditionRecordId({
      domain_id: "dom-a",
      condition_type: "missing",
      subject_key: "example.test",
    });
    ok("MUTANT colliding condition namespaces make identity fixture red",
      weak === missing);
  },
);

await withMutant(
  lib,
  "dmarc-ingest.js",
  'np: _enumValue(policyBlock, "np", DMARC_POLICY_VALUES, { required: false }),',
  "np: null,",
  async (mutant) => {
    const parsed = mutant.parseDmarcAggregateXml(`
      <feedback xmlns="urn:ietf:params:xml:ns:dmarc-2.0">
        <version>1.0</version>
        <report_metadata>
          <org_name>Reporter</org_name><email>d@example.net</email>
          <report_id>r1</report_id>
          <date_range><begin>1700000000</begin><end>1700003600</end></date_range>
        </report_metadata>
        <policy_published>
          <domain>example.test</domain><p>reject</p><np>none</np>
        </policy_published>
        <record>
          <row><source_ip>192.0.2.1</source_ip><count>1</count>
            <policy_evaluated><disposition>reject</disposition><dkim>pass</dkim><spf>pass</spf></policy_evaluated>
          </row>
          <identifiers><header_from>example.test</header_from></identifiers>
          <auth_results><dkim><domain>example.test</domain><selector>s1</selector><result>pass</result></dkim></auth_results>
        </record>
      </feedback>`);
    ok("MUTANT dropped RFC 9990 np makes aggregate fixture red",
      parsed.policy_published?.np == null);
  },
);

console.log(`\nDMARCbis P2 mutations: ${pass} passed, ${fail} failed`);
if (fail) process.exit(1);
