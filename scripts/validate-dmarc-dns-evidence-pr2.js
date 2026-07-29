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
const SPF_RESOLVER_PATH = path.join(ROOT, "workers/scan-api/src/engines/spf-resolver.js");
const SCAN_BUDGET_PATH = path.join(ROOT, "workers/scan-api/src/engines/scan-budget.js");
const POSTURE_EVENTS_PATH = path.join(ROOT, "workers/scan-api/src/engines/posture-events.js");

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

function rewriteImports(source, overrides = {}) {
  const rewritten = source
    .replace('import { dnsQuery } from "./dns.js";', `import { dnsQuery } from ${JSON.stringify(overrides.dnsUrl || pathToFileURL(DNS_PATH).href)};`)
    .replace('import { deriveDmarcState } from "./dmarc-state.js";', `import { deriveDmarcState } from ${JSON.stringify(pathToFileURL(STATE_PATH).href)};`)
    .replace('import { makeDohSpfLookup, resolveSpfAuthorization, SPF_RESOLUTION_STATUS } from "./spf-resolver.js";', `import { makeDohSpfLookup, resolveSpfAuthorization, SPF_RESOLUTION_STATUS } from ${JSON.stringify(pathToFileURL(SPF_RESOLVER_PATH).href)};`)
    .replace('import { makeDohSpfLookup, resolveSpfAuthorization } from "./spf-resolver.js";', `import { makeDohSpfLookup, resolveSpfAuthorization } from ${JSON.stringify(pathToFileURL(SPF_RESOLVER_PATH).href)};`)
    .replace('from "./email-analysis.js";', `from ${JSON.stringify(pathToFileURL(ANALYSIS_PATH).href)};`)
    // Email Deadline P1: email-scan.js now depends directly on the REAL
    // scan-budget.js for the canonical deadline fallback. The sandbox copy must
    // resolve the exact reviewed implementation — never a shim or a partial —
    // so deadline behaviour is what production runs.
    .replace('import { markDeadlineDeferred } from "./scan-budget.js";', `import { markDeadlineDeferred } from ${JSON.stringify(pathToFileURL(SCAN_BUDGET_PATH).href)};`);
  // Faithfulness guard: the sandboxed module must import the intended deadline
  // helper, and every relative import must have been rewritten to its exact
  // source module. A silently removed deadline import, or a NEW dependency this
  // rewriter does not know about, fails RED here — never a sandbox
  // ERR_MODULE_NOT_FOUND and never a quietly divergent copy.
  if (!source.includes('import { markDeadlineDeferred } from "./scan-budget.js";')) {
    throw new Error("email-scan.js no longer imports markDeadlineDeferred from ./scan-budget.js — the sandbox would diverge from the reviewed deadline behaviour");
  }
  const unresolved = [...rewritten.matchAll(/from\s+"\.\.?\/[^"]+"/g)].map((m) => m[0]);
  if (unresolved.length > 0) {
    throw new Error(`sandboxed email-scan.js has unrewritten relative imports: ${unresolved.join(", ")} — add exact-source rewrites for them`);
  }
  return rewritten;
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

async function importEmailScanWithDnsStub(source, label, zone) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), `spf-root-${label}-`));
  const dnsFile = path.join(dir, "dns-stub.mjs");
  const scanFile = path.join(dir, "email-scan.mjs");
  fs.writeFileSync(dnsFile, `
const zone = ${JSON.stringify(zone)};
export async function dnsQuery(name, type) {
  const entry = zone[\`\${String(name).toLowerCase()}|\${type}\`];
  if (entry?.reject) throw new Error(entry.reject);
  if (entry?.value) return entry.value;
  return { Status: 3, Answer: [] };
}
`);
  fs.writeFileSync(scanFile, rewriteImports(source, { dnsUrl: pathToFileURL(dnsFile).href }));
  try {
    return await import(`${pathToFileURL(scanFile).href}?t=${Date.now()}-${Math.random()}`);
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
const { buildPostureDiffEvents } = await import(pathToFileURL(POSTURE_EVENTS_PATH).href);

ok("exports DMARC observation enum", baselineMod.DMARC_OBSERVATION_STATUS?.UNAVAILABLE === "unavailable");
ok("exports DNS evidence builder", typeof baselineMod.buildDmarcEvidenceFromDnsResult === "function");
ok("email scan imports deriveDmarcState", /import \{ deriveDmarcState \} from "\.\/dmarc-state\.js";/.test(source));
ok("runEmailModule attaches non-enumerable canonical dmarc_state evidence", /Object\.defineProperty\(result, "dmarc_state"/.test(source));
ok("PR-2 does not JSON-serialize dmarc_state through normal details", !/dmarc_state: dmarcEvidence\.dmarc_state/.test(source));

runFixtures(baselineMod);

async function runEmailWithRootTxt(rootEntry, label, sourceOverride = source) {
  const mod = await importEmailScanWithDnsStub(sourceOverride, label, {
    "example.co.uk|TXT": rootEntry,
  });
  return mod.runEmailModule("example.co.uk");
}

function previousSpfModules() {
  return {
    email_security: {
      spf: {
        present: true,
        record: "v=spf1 ip4:192.0.2.0/24 -all",
        resolution_status: "complete",
        resolved_pass_authorisations: ["ip4:c0000200/24"],
      },
    },
  };
}

function spfEvents(currentEmail) {
  return buildPostureDiffEvents("example.co.uk", previousSpfModules(), { email_security: currentEmail })
    .filter((event) => event.event_type === "email_spf_changed" || event.event_type === "email_spf_authorization_changed");
}

// SPF root TXT evidence mirrors ADR-003: failed/unavailable lookup is not the same
// evidence state as an observed no-record result. A transient root failure must never
// be flattened to {present:false, complete empty set}, or it can create a false
// "SPF removed" event against a previous complete SPF snapshot.
{
  const current = await runEmailWithRootTxt({ value: { Status: 2, Answer: [] } }, "spf-servfail");
  eq("SPF SERVFAIL root lookup records temperror resolution", current.spf.resolution_status, "temperror");
  eq("SPF SERVFAIL root lookup has null resolved set", current.spf.resolved_pass_authorisations, null);
  const events = spfEvents(current);
  eq("SPF SERVFAIL emits zero SPF events", events.length, 0);
}

{
  const current = await runEmailWithRootTxt({ reject: "resolver rejected" }, "spf-rejected");
  eq("SPF rejected root lookup records temperror resolution", current.spf.resolution_status, "temperror");
  const events = spfEvents(current);
  eq("SPF rejected root lookup emits zero SPF events", events.length, 0);
}

{
  const current = await runEmailWithRootTxt({ value: { Status: 0, Answer: [] } }, "spf-no-record");
  eq("SPF observed no-record resolves as complete empty set", current.spf.resolution_status, "complete");
  ok("SPF observed no-record carries empty resolved set", Array.isArray(current.spf.resolved_pass_authorisations) && current.spf.resolved_pass_authorisations.length === 0);
  const events = spfEvents(current);
  const rootRemoval = events.find((event) => event.event_type === "email_spf_changed");
  ok("SPF observed no-record emits root SPF removal event", !!rootRemoval);
  eq("SPF observed no-record root removal severity is high", rootRemoval?.severity, "high");
}

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

const spfFailureCollapseMutation = {
  name: "spf_root_failure_collapsed_to_observed_absent",
  from: "const spfAuthorization = spfObservationStatus === DMARC_OBSERVATION_STATUS.OBSERVED",
  to: "const spfAuthorization = true",
};

{
  const mutated = replaceOnce(source, spfFailureCollapseMutation.from, spfFailureCollapseMutation.to, spfFailureCollapseMutation.name);
  const current = await runEmailWithRootTxt({ value: { Status: 2, Answer: [] } }, "mut-spf-servfail", mutated);
  const events = spfEvents(current);
  ok("mutation spf_root_failure_collapsed_to_observed_absent is caught by false-removal event",
    events.some((event) => event.event_type === "email_spf_changed"));
}

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
