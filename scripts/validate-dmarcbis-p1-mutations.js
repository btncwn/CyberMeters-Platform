#!/usr/bin/env node
// Item 7 P1 load-bearing mutation proof.
//
// Each mutation is applied to an actual P1 engine copy beside the original so
// relative imports and the pinned Worker dependency remain real. The named
// protocol defect must reappear; otherwise the corresponding fixture is not
// load-bearing.
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const engines = path.join(root, "workers", "scan-api", "src", "engines");
let pass = 0;
let fail = 0;
let sequence = 0;

const ok = (name, condition, detail = "") => {
  condition ? pass += 1 : fail += 1;
  if (condition) console.log(`ok - ${name}`);
  else console.error(`not ok - ${name}${detail ? `: ${detail}` : ""}`);
};
const eq = (name, actual, expected) =>
  ok(name, JSON.stringify(actual) === JSON.stringify(expected),
    `expected ${JSON.stringify(expected)}, got ${JSON.stringify(actual)}`);

async function withMutant(file, mutate, run) {
  const sourcePath = path.join(engines, file);
  const source = fs.readFileSync(sourcePath, "utf8");
  const mutated = mutate(source);
  ok(`${file} mutation applied`, mutated !== source);
  if (mutated === source) return;
  const mutantPath = path.join(
    engines,
    `.${file.replace(/\.js$/, "")}.mutant.${process.pid}.${++sequence}.js`,
  );
  fs.writeFileSync(mutantPath, mutated);
  try {
    const module = await import(`${pathToFileURL(mutantPath).href}?mutation=${sequence}`);
    await run(module);
  } finally {
    fs.rmSync(mutantPath, { force: true });
  }
}

function replaceOnce(source, from, to) {
  if (!source.includes(from)) return source;
  return source.replace(from, to);
}

function replaceLast(source, from, to) {
  const index = source.lastIndexOf(from);
  if (index === -1) return source;
  return `${source.slice(0, index)}${to}${source.slice(index + from.length)}`;
}

const TXT = (...values) => ({
  outcome: "success",
  txt_records: values.map((value) => ({ chunks: [value] })),
});
const NODATA = Object.freeze({ outcome: "nodata", txt_records: [] });
const NXDOMAIN = Object.freeze({ outcome: "nxdomain", txt_records: [] });
const TIMEOUT = Object.freeze({ outcome: "timeout" });

function dnsFixture(zone = {}) {
  const questions = [];
  const dns = async (question) => {
    questions.push(question);
    const resolverKey = `${question.resolver}|${question.type}|${question.name}`.toLowerCase();
    const genericKey = `${question.type}|${question.name}`.toLowerCase();
    return zone[resolverKey] ?? zone[genericKey] ?? NODATA;
  };
  dns.questions = questions;
  return dns;
}

function set(zone, name, type, value, resolver = null) {
  zone[
    (resolver ? `${resolver}|${type}|${name}` : `${type}|${name}`).toLowerCase()
  ] = value;
}

function exactZone(record) {
  const zone = {};
  set(zone, "_dmarc.example.test", "TXT", TXT(record));
  set(zone, "_dmarc.test", "TXT", NODATA);
  return zone;
}

async function childPolicy(mod, existence) {
  const zone = {};
  set(zone, "_dmarc.mail.example.test", "TXT", NODATA);
  set(zone, "_dmarc.example.test", "TXT",
    TXT("v=DMARC1; p=none; sp=quarantine; np=reject; psd=n"));
  set(zone, "mail.example.test", "A", existence);
  return mod.resolveDmarcbisPolicy({
    authorDomain: "mail.example.test",
    dns: dnsFixture(zone),
  });
}

// Multiple policy candidates must all be discarded.
await withMutant(
  "dmarcbis-parser.js",
  (source) => replaceOnce(source, "if (candidates.length > 1) {", "if (candidates.length > 2) {"),
  async (mod) => {
    const result = mod.parseDmarcbisPolicyRecordSet([
      "v=DMARC1; p=none",
      "v=DMARC1; p=reject",
    ]);
    ok("MUTANT candidate-count makes the two-record fixture red",
      !["multiple", "multiple_mixed", "multiple_invalid"].includes(result.raw_state));
  },
);

// Duplicate tags must never become an arbitrary selected policy.
await withMutant(
  "dmarcbis-parser.js",
  (source) => replaceOnce(
    source,
    "const duplicateFatal = initial.duplicate_tags.length > 0;",
    "const duplicateFatal = false;",
  ),
  async (mod) => {
    const result = mod.parseDmarcbisPolicyRecordSet(["v=DMARC1; p=none; p=reject"]);
    ok("MUTANT duplicate-tag acceptance makes the duplicate fixture red", result.selected !== null);
  },
);

// RFC 9989 §4.8 ignores malformed remainder syntax after a valid version tag.
await withMutant(
  "dmarcbis-parser.js",
  (source) => replaceOnce(
    source,
    "const normalPolicy = !duplicateFatal && !invalidPolicyTag;",
    "const normalPolicy = !duplicateFatal && !invalidPolicyTag && initial.errors.length === 0;",
  ),
  async (mod) => {
    const result = mod.parseDmarcbisPolicyRecord(
      "v=DMARC1; p=reject; syntactically-broken",
    );
    ok("MUTANT fatal remainder syntax makes the RFC default-or-ignore fixture red",
      !result.valid_for_discovery);
  },
);

// Aggregate evidence must not be prefix-selected after the 256 KiB bound.
await withMutant(
  "dmarcbis-parser.js",
  (source) => replaceOnce(
    source,
    "aggregateBytes > DMARCBIS_MAX_DNS_EVIDENCE_BYTES",
    "aggregateBytes > Number.MAX_SAFE_INTEGER",
  ),
  async (mod) => {
    const result = mod.parseDmarcbisPolicyRecordSet(
      Array.from({ length: 5 }, (_, index) =>
        `v=DMARC1; p=reject; x${index}=${"a".repeat(54 * 1024)}`),
    );
    ok("MUTANT removed aggregate bound makes the byte-limit fixture red",
      result.raw_state !== "incomplete_oversized");
  },
);

// Authorization evidence has the same aggregate no-prefix-selection boundary.
await withMutant(
  "dmarcbis-parser.js",
  (source) => replaceLast(
    source,
    "aggregateBytes > DMARCBIS_MAX_DNS_EVIDENCE_BYTES",
    "aggregateBytes > Number.MAX_SAFE_INTEGER",
  ),
  async (mod) => {
    const result = mod.parseDmarcbisAuthorizationRecordSet(
      ["xa", "xb", "xc", "xd", "xe"].map(
        (tag) => `v=DMARC1; ${tag}=${"a".repeat(60 * 1024)}`,
      ),
    );
    ok("MUTANT removed authorization aggregate bound makes its fixture red",
      result.record_state !== "incomplete_oversized");
  },
);

// The version value is case-sensitive.
await withMutant(
  "dmarcbis-parser.js",
  (source) => replaceOnce(
    source,
    'first.normalized_value === "DMARC1"',
    'first.normalized_value.toUpperCase() === "DMARC1"',
  ),
  async (mod) => {
    ok("MUTANT case-insensitive version makes the wrong-case fixture red",
      mod.parseDmarcbisPolicyRecord("v=dmarc1; p=reject").is_current_version);
  },
);

// The version tag must be first.
await withMutant(
  "dmarcbis-parser.js",
  (source) => replaceOnce(
    source,
    "const first = tags[0] || null;",
    'const first = tags.find((tag) => tag.name === "v") || null;',
  ).replace("first?.index === 0 &&", "first &&"),
  async (mod) => {
    ok("MUTANT later-version acceptance makes the first-tag fixture red",
      mod.parseDmarcbisPolicyRecord("p=reject; v=DMARC1").is_current_version);
  },
);

// Deep names must jump directly to seven labels.
await withMutant(
  "dmarcbis-resolver.js",
  (source) => replaceOnce(source, "labels = labels.slice(-7);", "labels = labels.slice(1);"),
  async (mod) => {
    const plan = mod.planDmarcbisTreeWalk("a.b.c.d.e.f.g.h.i.j.mail.example.com");
    ok("MUTANT forbidden intermediate deep-label query makes the walk fixture red",
      plan.questions[1].name !== "_dmarc.g.h.i.j.mail.example.com");
  },
);

// Tree walks cannot issue a ninth logical TXT question.
await withMutant(
  "dmarcbis-resolver.js",
  (source) => replaceOnce(
    replaceOnce(source, "labels = labels.slice(-7);", "labels = labels.slice(1);"),
    "questions.length < DMARCBIS_MAX_TREE_QUESTIONS",
    "questions.length <= DMARCBIS_MAX_TREE_QUESTIONS",
  ),
  async (mod) => {
    const plan = mod.planDmarcbisTreeWalk("a.b.c.d.e.f.g.h.i.j.mail.example.com");
    eq("MUTANT ninth question makes the cap fixture red", plan.questions.length, 9);
  },
);

// A sole psd=y/n record is a normative logical stop.
await withMutant(
  "dmarcbis-resolver.js",
  (source) => replaceOnce(
    source,
    '["y", "n"].includes(soleCandidate.psd.normalized)',
    '[].includes(soleCandidate.psd.normalized)',
  ),
  async (mod) => {
    const zone = {};
    set(zone, "_dmarc.mail.example.test", "TXT", NODATA);
    set(zone, "_dmarc.example.test", "TXT", TXT("v=DMARC1; p=reject; psd=y"));
    const result = await mod.resolveDmarcbisPolicy({
      authorDomain: "mail.example.test",
      dns: dnsFixture(zone),
    });
    ok("MUTANT ignored psd stop makes the stop fixture red", result.tree_walk.stop_reason !== "psd_y");
  },
);

// An unusable exact candidate cannot stop the parent walk with its psd tag.
await withMutant(
  "dmarcbis-resolver.js",
  (source) => replaceOnce(
    source,
    "const stopEligible = index > 0 || Boolean(recordSet.selected);",
    "const stopEligible = true;",
  ),
  async (mod) => {
    const zone = {};
    set(
      zone,
      "_dmarc.mail.example.test",
      "TXT",
      TXT("v=DMARC1; p=invalid; psd=n"),
    );
    set(
      zone,
      "_dmarc.example.test",
      "TXT",
      TXT("v=DMARC1; p=reject; psd=n"),
    );
    const result = await mod.resolveDmarcbisPolicy({
      authorDomain: "mail.example.test",
      dns: dnsFixture(zone),
    });
    ok("MUTANT unusable exact psd stop makes parent-inheritance fixture red",
      result.policy_source_domain === null);
  },
);

// NXDOMAIN and NODATA cannot collapse.
await withMutant(
  "dmarcbis-resolver.js",
  (source) => replaceOnce(
    source,
    'return { state: "nonexistent", completeness: "complete", observation };',
    'return { state: "exists", completeness: "complete", observation };',
  ),
  async (mod) => {
    const result = await childPolicy(mod, NXDOMAIN);
    ok("MUTANT NXDOMAIN-to-NODATA collapse makes existence fixture red",
      result.domain_existence === "exists" && result.effective_policy_tag === "sp");
  },
);

// Nonexistent children select np before sp/p.
await withMutant(
  "dmarcbis-resolver.js",
  (source) => replaceOnce(
    source,
    'existence.state === "nonexistent" && record.np.present',
    'false && record.np.present',
  ),
  async (mod) => {
    const result = await childPolicy(mod, NXDOMAIN);
    ok("MUTANT np precedence makes the applicability fixture red",
      result.effective_policy_tag !== "np" && result.effective_requested_policy !== "reject");
  },
);

// An sp-only source has the same result for existing and nonexistent children.
await withMutant(
  "dmarcbis-resolver.js",
  (source) => replaceOnce(
    source,
    "source.entry.record.np.present,",
    "(source.entry.record.sp.present || source.entry.record.np.present),",
  ),
  async (mod) => {
    const zone = {};
    set(zone, "_dmarc.mail.example.test", "TXT", NODATA);
    set(zone, "_dmarc.example.test", "TXT",
      TXT("v=DMARC1; p=none; sp=reject; psd=n"));
    set(zone, "mail.example.test", "A", TIMEOUT);
    const result = await mod.resolveDmarcbisPolicy({
      authorDomain: "mail.example.test",
      dns: dnsFixture(zone),
    });
    ok("MUTANT needless sp existence lookup makes the budget fixture red",
      result.effective_requested_policy === null);
  },
);

// RFC 9989 §4.7 maps reject+t=y to quarantine, not none.
await withMutant(
  "dmarcbis-resolver.js",
  (source) => replaceOnce(
    source,
    'effective_requested_policy: declaredPolicy === "reject" ? "quarantine" : "none",',
    'effective_requested_policy: "none",',
  ),
  async (mod) => {
    const result = await mod.resolveDmarcbisPolicy({
      authorDomain: "example.test",
      dns: dnsFixture(exactZone("v=DMARC1; p=reject; t=y; psd=n")),
    });
    eq("MUTANT collapsed t ladder makes the direct-clause fixture red",
      result.effective_requested_policy, "none");
  },
);

// Legacy pct must never change current effective policy.
await withMutant(
  "dmarcbis-resolver.js",
  (source) => replaceOnce(
    source,
    "const prefix = source.kind === \"psd\" ? \"psd\" : \"organisational\";",
    `if (record.legacy_pct?.numeric != null && record.legacy_pct.numeric < 100) {
    declaredPolicy = "none";
  }
  const prefix = source.kind === "psd" ? "psd" : "organisational";`,
  ),
  async (mod) => {
    const result = await mod.resolveDmarcbisPolicy({
      authorDomain: "example.test",
      dns: dnsFixture(exactZone("v=DMARC1; p=reject; pct=25; psd=n")),
    });
    eq("MUTANT pct application makes the legacy fixture red",
      result.effective_requested_policy, "none");
  },
);

// Temporary provider failure must not become observed absence.
await withMutant(
  "dmarcbis-resolver.js",
  (source) => replaceOnce(
    source,
    'else if (status === 2) outcome = "servfail";',
    'else if (status === 2) outcome = "nodata";',
  ),
  async (mod) => {
    const dns = dnsFixture({
      "txt|_dmarc.example.test": { Status: 2, Answer: [] },
    });
    const result = await mod.resolveDmarcbisPolicy({
      authorDomain: "example.test",
      dns,
    });
    ok("MUTANT SERVFAIL-to-empty makes the availability fixture red",
      result.observation_state === "absent");
  },
);

// A nominally successful but unresolved truncated DNS response is unavailable.
await withMutant(
  "dmarcbis-resolver.js",
  (source) => replaceOnce(
    source,
    'if (truncated) outcome = "truncated_unresolved";',
    'if (truncated && false) outcome = "truncated_unresolved";',
  ),
  async (mod) => {
    const result = await mod.resolveDmarcbisPolicy({
      authorDomain: "example.test",
      dns: dnsFixture({
        "txt|_dmarc.example.test": {
          outcome: "success",
          truncated: true,
          txt_records: [{ chunks: ["v=DMARC1; p=reject; psd=n"] }],
        },
      }),
    });
    eq("MUTANT truncated-success parsing makes the truncation fixture red",
      result.effective_requested_policy, "reject");
  },
);

// An unrecognizable provider object is malformed, never implicit NODATA.
await withMutant(
  "dmarcbis-resolver.js",
  (source) => replaceOnce(
    source,
    `} else {
      outcome = "malformed_response";
    }
  }
  if (outcome === "success"`,
    `} else {
      outcome = "nodata";
    }
  }
  if (outcome === "success"`,
  ),
  async (mod) => {
    const result = await mod.resolveDmarcbisPolicy({
      authorDomain: "example.test",
      dns: dnsFixture({
        "txt|_dmarc.example.test": {},
      }),
    });
    eq("MUTANT shape-less response makes malformed-response fixture red",
      result.observation_state, "absent");
  },
);

// Resolver disagreement cannot be resolved by selecting primary.
await withMutant(
  "dmarcbis-resolver.js",
  (source) => source
    .replace(
      "existence.state === \"unknown\" ||\n    disagreement;",
      "existence.state === \"unknown\";",
    )
    .replace("const policy = disagreement || policyUnavailable", "const policy = policyUnavailable"),
  async (mod) => {
    const zone = exactZone("v=DMARC1; p=reject; psd=n");
    set(zone, "_dmarc.example.test", "TXT", TXT("v=DMARC1; p=none; psd=n"), "secondary");
    const result = await mod.resolveDmarcbisPolicy({
      authorDomain: "example.test",
      dns: dnsFixture(zone),
    });
    eq("MUTANT preferred-resolver selection makes disagreement fixture red",
      result.effective_requested_policy, "reject");
  },
);

async function externalPolicy(parserMod, rua) {
  const record = parserMod.parseDmarcbisPolicyRecord(
    `v=DMARC1; p=reject; psd=n; rua=${rua}`,
  );
  return {
    policy_source_domain: "example.test",
    organisational_domain: "example.test",
    rua_destinations: record.rua,
  };
}

async function externalZone(authRecord = TXT("v=DMARC1")) {
  const zone = {};
  set(zone, "_dmarc.reports.external.test", "TXT", NODATA);
  set(zone, "_dmarc.external.test", "TXT", TXT("v=DMARC1; p=none; psd=n"));
  set(zone, "example.test._report._dmarc.reports.external.test", "TXT", authRecord);
  return zone;
}

const realParser = await import(
  pathToFileURL(path.join(engines, "dmarcbis-parser.js")).href
);

// RFC 9990 authorises when at least one record passes, not exactly one.
await withMutant(
  "dmarcbis-parser.js",
  (source) => replaceOnce(
    source,
    "authorized: valid_records.length > 0,",
    "authorized: valid_records.length === 1,",
  ),
  async (mod) => {
    const setResult = mod.parseDmarcbisAuthorizationRecordSet([
      "v=DMARC1",
      "v=DMARC1; x=one",
    ]);
    ok("MUTANT exactly-one authorization makes RFC 9990 fixture red", !setResult.authorized);
  },
);

// Corroboration compares all current authorization candidates, not successes only.
await withMutant(
  "dmarcbis-resolver.js",
  (source) => replaceOnce(
    source,
    "set?.current_records || []",
    "set?.valid_records || []",
  ),
  async (mod) => {
    const zone = await externalZone(TXT("v=DMARC1", "v=DMARC1; rua"));
    set(
      zone,
      "example.test._report._dmarc.reports.external.test",
      "TXT",
      TXT("v=DMARC1"),
      "secondary",
    );
    const result = await mod.resolveDmarcbisExternalRuaAuthorizations({
      policyEvidence: await externalPolicy(
        realParser,
        "mailto:dmarc@reports.external.test",
      ),
      dns: dnsFixture(zone),
    });
    eq("MUTANT success-only authorization fingerprint makes disagreement fixture red",
      result.destinations[0].authorization_status, "authorized");
  },
);

// Full per-host reservation must happen before any destination DNS.
await withMutant(
  "dmarcbis-resolver.js",
  (source) => replaceOnce(source, "if (!reserved) {", "if (!reserved && false) {"),
  async (mod) => {
    const dns = dnsFixture(await externalZone());
    await mod.resolveDmarcbisExternalRuaAuthorizations({
      policyEvidence: await externalPolicy(realParser, "mailto:dmarc@reports.external.test"),
      dns,
      reserveHost: () => false,
    });
    ok("MUTANT partial-host launch makes budget fixture red", dns.questions.length > 0);
  },
);

// Reused host authorization must preserve each original URI when no override exists.
await withMutant(
  "dmarcbis-resolver.js",
  (source) => replaceOnce(
    source,
    "results.push(reuseHostAssessment(uri, hostResults.get(uri.destination_host)));",
    "results.push({ ...uri, ...hostResults.get(uri.destination_host), reused_host_assessment: true });",
  ),
  async (mod) => {
    const result = await mod.resolveDmarcbisExternalRuaAuthorizations({
      policyEvidence: await externalPolicy(
        realParser,
        "mailto:first@reports.external.test,mailto:second@reports.external.test",
      ),
      dns: dnsFixture(await externalZone()),
    });
    eq("MUTANT reused first URI makes same-host reuse fixture red",
      result.destinations[1].authorized_destination,
      "mailto:first@reports.external.test");
  },
);

// Different-host authorization overrides are prohibited.
await withMutant(
  "dmarcbis-resolver.js",
  (source) => replaceOnce(
    source,
    "entry.destination_host !== destinationHost",
    "entry.destination_host === destinationHost",
  ),
  async (mod) => {
    const zone = await externalZone(
      TXT("v=DMARC1; rua=mailto:replacement@second.example"),
    );
    const result = await mod.resolveDmarcbisExternalRuaAuthorizations({
      policyEvidence: await externalPolicy(realParser, "mailto:dmarc@reports.external.test"),
      dns: dnsFixture(zone),
    });
    ok("MUTANT second-hop acceptance makes override fixture red",
      result.destinations[0].destination_usability !== "prohibited_second_hop");
  },
);

// Destination overflow must force incompleteness and prohibit all-authorized.
await withMutant(
  "dmarcbis-resolver.js",
  (source) => replaceOnce(
    source,
    "if (index >= DMARCBIS_MAX_REPORT_URIS) {",
    "if (index > DMARCBIS_MAX_REPORT_URIS) {",
  ),
  async (mod) => {
    const uris = Array.from({ length: 11 }, (_, index) =>
      `mailto:r${index}@reports.external.test`).join(",");
    const result = await mod.resolveDmarcbisExternalRuaAuthorizations({
      policyEvidence: await externalPolicy(realParser, uris),
      dns: dnsFixture(await externalZone()),
    });
    ok("MUTANT URI overflow makes the destination-bound fixture red",
      result.destinations[10].assessment_reason !== "uri_count_limit");
  },
);

// DNS authorisation must not expand inbound RUA authority.
await withMutant(
  "dmarcbis-resolver.js",
  (source) => source.replaceAll(
    'trusted_ingestion_status: "observational_item5_gate_required",',
    'trusted_ingestion_status: "authoritative",',
  ),
  async (mod) => {
    const result = await mod.resolveDmarcbisExternalRuaAuthorizations({
      policyEvidence: await externalPolicy(realParser, "mailto:dmarc@reports.external.test"),
      dns: dnsFixture(await externalZone()),
    });
    eq("MUTANT trust expansion makes the Item 5 boundary fixture red",
      result.destinations[0].trusted_ingestion_status, "authoritative");
  },
);

// The approved UTS #46 profile keeps joiner validation enabled.
await withMutant(
  "dmarcbis-idna.js",
  (source) => replaceOnce(
    source,
    "checkJoiners: true,",
    "checkJoiners: false,",
  ),
  async (mod) => {
    ok("MUTANT disabled joiner check makes the IDNA fixture red",
      mod.canonicalizeDmarcbisDomain("a\u200db.example").ok);
  },
);

console.log(`\nDMARCbis P1 mutation proofs: ${pass} passed, ${fail} failed`);
if (fail) process.exit(1);
