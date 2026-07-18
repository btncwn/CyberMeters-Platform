// ADR-003 PR-2 validator: DMARC DNS observation status at the scan boundary.
// Proves failed/unexecuted DMARC lookups cannot collapse into observed absence
// before canonical deriveDmarcState() evaluation.

import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { pathToFileURL } from "node:url";

let pass = 0;
let fail = 0;
const failures = [];

function ok(name, condition, detail = "") {
  if (condition) {
    pass += 1;
    console.log(`ok - ${name}`);
  } else {
    fail += 1;
    failures.push(`${name}${detail ? `: ${detail}` : ""}`);
    console.error(`not ok - ${name}${detail ? `: ${detail}` : ""}`);
  }
}

function eq(name, actual, expected) {
  ok(name, actual === expected, `expected ${JSON.stringify(expected)}, got ${JSON.stringify(actual)}`);
}

const ROOT = process.cwd();
const EMAIL_SCAN_PATH = path.join(ROOT, "workers/scan-api/src/engines/email-scan.js");
const DNS_PATH = path.join(ROOT, "workers/scan-api/src/engines/dns.js");
const ANALYSIS_PATH = path.join(ROOT, "workers/scan-api/src/engines/email-analysis.js");
const STATE_PATH = path.join(ROOT, "workers/scan-api/src/engines/dmarc-state.js");

function settled(value) {
  return { status: "fulfilled", value };
}

function txt(data) {
  return { type: 16, data };
}

const FIXTURES = [
  {
    name: "timeout_rejected_not_observed",
    input: { status: "rejected", reason: new Error("timeout") },
    expected: { evidence_status: "unavailable", record_presence: "unknown", enforcement_level: "not_observed", record_count: 0 },
  },
  {
    name: "servfail_not_observed",
    input: settled({ Status: 2, Answer: [] }),
    expected: { evidence_status: "unavailable", record_presence: "unknown", enforcement_level: "not_observed", record_count: 0 },
  },
  {
    name: "rejected_promise_not_observed",
    input: { status: "rejected", reason: new Error("resolver rejected") },
    expected: { evidence_status: "unavailable", record_presence: "unknown", enforcement_level: "not_observed", record_count: 0 },
  },
  {
    name: "not_executed_not_yet_assessed",
    input: { status: "not_executed" },
    expected: { evidence_status: "not_yet_assessed", record_presence: "unknown", enforcement_level: "not_yet_assessed", record_count: 0 },
  },
  {
    name: "nxdomain_zero_result_no_record",
    input: settled({ Status: 3, Answer: [] }),
    expected: { evidence_status: "observed", record_presence: "absent", enforcement_level: "no_record", record_count: 0 },
  },
  {
    name: "noerror_zero_result_no_record",
    input: settled({ Status: 0, Answer: [] }),
    expected: { evidence_status: "observed", record_presence: "absent", enforcement_level: "no_record", record_count: 0 },
  },
  {
    name: "observed_valid_reject_preserved",
    input: settled({ Status: 0, Answer: [txt("v=DMARC1; p=reject; rua=mailto:dmarc@example.com")] }),
    expected: { evidence_status: "observed", record_presence: "present", enforcement_level: "reject_enforced", record_count: 1 },
  },
  {
    name: "resolver_disagreement_not_observed",
    input: settled({
      Status: 0,
      Answer: [txt("v=DMARC1; p=reject; rua=mailto:dmarc@example.com")],
      resolver_disagreement: true,
      resolver_agreement_score: 50,
    }),
    expected: { evidence_status: "unavailable", record_presence: "unknown", enforcement_level: "not_observed", record_count: 0 },
  },
  {
    name: "servfail_with_answer_still_not_observed",
    input: settled({ Status: 2, Answer: [txt("v=DMARC1; p=reject; rua=mailto:dmarc@example.com")] }),
    expected: { evidence_status: "unavailable", record_presence: "unknown", enforcement_level: "not_observed", record_count: 0 },
  },
];

function fixtureReason(mod, fixture) {
  let evidence;
  try {
    evidence = mod.buildDmarcEvidenceFromDnsResult(fixture.input, {
      last_observed: "2026-07-18T12:00:00.000Z",
    });
  } catch (err) {
    return `${fixture.name}: threw ${err?.message || err}`;
  }
  const expected = fixture.expected;
  if (evidence.dmarc_state.evidence_status !== expected.evidence_status) {
    return `${fixture.name}: evidence_status expected ${expected.evidence_status}, got ${evidence.dmarc_state.evidence_status}`;
  }
  if (evidence.dmarc_state.record_presence !== expected.record_presence) {
    return `${fixture.name}: record_presence expected ${expected.record_presence}, got ${evidence.dmarc_state.record_presence}`;
  }
  if (evidence.dmarc_state.enforcement_level !== expected.enforcement_level) {
    return `${fixture.name}: enforcement_level expected ${expected.enforcement_level}, got ${evidence.dmarc_state.enforcement_level}`;
  }
  if (evidence.dmarc_detail.record_count !== expected.record_count) {
    return `${fixture.name}: record_count expected ${expected.record_count}, got ${evidence.dmarc_detail.record_count}`;
  }
  return null;
}

function rewriteImports(source) {
  return source
    .replace('import { dnsQuery } from "./dns.js";', `import { dnsQuery } from ${JSON.stringify(pathToFileURL(DNS_PATH).href)};`)
    .replace('import { deriveDmarcState } from "./dmarc-state.js";', `import { deriveDmarcState } from ${JSON.stringify(pathToFileURL(STATE_PATH).href)};`)
    .replace('from "./email-analysis.js";', `from ${JSON.stringify(pathToFileURL(ANALYSIS_PATH).href)};`);
}

async function importEmailScanFromSource(source, label) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), `dmarc-pr2-${label}-`));
  const file = path.join(dir, "email-scan.mjs");
  fs.writeFileSync(file, rewriteImports(source));
  try {
    return await import(`${pathToFileURL(file).href}?t=${Date.now()}-${Math.random()}`);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

function runFixtures(mod) {
  for (const fixture of FIXTURES) {
    const reason = fixtureReason(mod, fixture);
    ok(`fixture ${fixture.name}`, reason === null, reason || "");
  }
}

function replaceOnce(source, from, to, mutationName) {
  if (!source.includes(from)) {
    throw new Error(`${mutationName}: source snippet not found`);
  }
  return source.replace(from, to);
}

async function mutationFailureReason(source, mutation) {
  const mutated = replaceOnce(source, mutation.from, mutation.to, mutation.name);
  const mod = await importEmailScanFromSource(mutated, `mut-${mutation.name}`);
  const intended = FIXTURES.find((fixture) => fixture.name === mutation.expected);
  const fixtures = intended
    ? [intended, ...FIXTURES.filter((fixture) => fixture.name !== mutation.expected)]
    : FIXTURES;
  for (const fixture of fixtures) {
    const reason = fixtureReason(mod, fixture);
    if (reason) return reason;
  }
  return null;
}

const source = fs.readFileSync(EMAIL_SCAN_PATH, "utf8");
const baselineMod = await import(pathToFileURL(EMAIL_SCAN_PATH).href);

ok("exports DMARC observation enum", baselineMod.DMARC_OBSERVATION_STATUS?.UNAVAILABLE === "unavailable");
ok("exports DNS evidence builder", typeof baselineMod.buildDmarcEvidenceFromDnsResult === "function");
ok("email scan imports deriveDmarcState", /import \{ deriveDmarcState \} from "\.\/dmarc-state\.js";/.test(source));
ok("runEmailModule attaches non-enumerable canonical dmarc_state evidence", /Object\.defineProperty\(result, "dmarc_state"/.test(source));
ok("PR-2 does not JSON-serialize dmarc_state through normal details", !/dmarc_state: dmarcEvidence\.dmarc_state/.test(source));

runFixtures(baselineMod);

const MUTATIONS = [
  {
    name: "timeout_collapsed_to_empty_result",
    from: 'if (settledResult.status !== "fulfilled") return DMARC_OBSERVATION_STATUS.UNAVAILABLE;',
    to: 'if (settledResult.status !== "fulfilled") return DMARC_OBSERVATION_STATUS.OBSERVED;',
    expected: "timeout_rejected_not_observed",
  },
  {
    name: "servfail_collapsed_to_empty_result",
    from: "if (dnsStatus === DNS_STATUS_NOERROR || dnsStatus === DNS_STATUS_NXDOMAIN) {",
    to: "if (dnsStatus === DNS_STATUS_NOERROR || dnsStatus === DNS_STATUS_NXDOMAIN || dnsStatus === 2) {",
    expected: "servfail_not_observed",
  },
  {
    name: "not_executed_collapsed_to_missing",
    from: "if (isNotExecutedDmarcLookup(settledResult)) return DMARC_OBSERVATION_STATUS.NOT_YET_ASSESSED;",
    to: "if (isNotExecutedDmarcLookup(settledResult)) return DMARC_OBSERVATION_STATUS.OBSERVED;",
    expected: "not_executed_not_yet_assessed",
  },
  {
    name: "nxdomain_no_record_treated_unavailable",
    from: "if (dnsStatus === DNS_STATUS_NOERROR || dnsStatus === DNS_STATUS_NXDOMAIN) {",
    to: "if (dnsStatus === DNS_STATUS_NOERROR) {",
    expected: "nxdomain_zero_result_no_record",
  },
  {
    name: "observed_valid_record_treated_unavailable",
    from: "return DMARC_OBSERVATION_STATUS.OBSERVED;\n  }\n  return DMARC_OBSERVATION_STATUS.UNAVAILABLE;",
    to: "return DMARC_OBSERVATION_STATUS.UNAVAILABLE;\n  }\n  return DMARC_OBSERVATION_STATUS.UNAVAILABLE;",
    expected: "observed_valid_reject_preserved",
  },
  {
    name: "resolver_disagreement_treated_observed",
    from: "if (hasResolverDisagreement(response)) return DMARC_OBSERVATION_STATUS.UNAVAILABLE;",
    to: "if (hasResolverDisagreement(response)) return DMARC_OBSERVATION_STATUS.OBSERVED;",
    expected: "resolver_disagreement_not_observed",
  },
  {
    name: "evidence_status_ignored_before_presence",
    from: "evidence_status: observationStatus,",
    to: 'evidence_status: "observed",',
    expected: "servfail_with_answer_still_not_observed",
  },
];

let mutationFailures = 0;
for (const mutation of MUTATIONS) {
  const reason = await mutationFailureReason(source, mutation);
  const failedForExpectedFixture = reason?.includes(mutation.expected);
  ok(`mutation ${mutation.name} fails for intended reason`, failedForExpectedFixture, reason || "mutation survived");
  if (!failedForExpectedFixture) mutationFailures += 1;
}

ok("all PR-2 mutations were killed", mutationFailures === 0);

if (fail) {
  console.error("\nFailures:");
  for (const failure of failures) console.error(`- ${failure}`);
  process.exit(1);
}

console.log(`\nDMARC DNS evidence PR-2: ${pass}/${pass + fail} passed`);
