#!/usr/bin/env node
//
// ADR-003 canonical DMARC state validator.
//
// Pure-function harness only: no DNS, no D1/R2, no API, no frontend, no scoring,
// no reporting, no hosted-DMARC behaviour, and no production consumer switch.
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const statePath = path.join(root, "workers", "scan-api", "src", "engines", "dmarc-state.js");
const parserPath = path.join(root, "workers", "scan-api", "src", "engines", "email-analysis.js");

const realState = await import(pathToFileURL(statePath).href);
const { parseDmarcRecord } = await import(pathToFileURL(parserPath).href);

let pass = 0, fail = 0;
const ok = (name, cond, detail = "") => {
  cond ? pass++ : fail++;
  if (!cond) console.log(`FAIL ${name}${detail ? ` -- ${detail}` : ""}`);
};
const eq = (name, actual, expected) => ok(name, actual === expected, `got ${JSON.stringify(actual)}, expected ${JSON.stringify(expected)}`);

const OBSERVED_AT = "2026-07-18T15:00:00.000Z";
const REQUIRED_FIELDS = [
  "evidence_status",
  "record_presence",
  "record_validity",
  "invalid_reason",
  "policy",
  "pct",
  "subdomain_policy",
  "policy_source",
  "enforcement_level",
  "caveats",
  "confidence",
  "last_observed",
  "state_model_version",
];
const CANONICAL_LEVELS = [
  "not_yet_assessed",
  "not_observed",
  "no_record",
  "invalid_record",
  "monitoring",
  "partial_quarantine",
  "quarantine_enforced",
  "partial_reject",
  "reject_enforced",
];
const CANONICAL_CAVEAT_ORDER = [
  "policy_applies_to_zero_percent",
  "subdomain_gap",
  "pct_below_100",
];

const dmarc = (record, count = record ? 1 : 0) => parseDmarcRecord(record, count);
const input = (record, count, extra = {}) => ({
  dmarc: dmarc(record, count),
  last_observed: OBSERVED_AT,
  ...extra,
});

const fixtures = [
  {
    name: "never_assessed",
    input: { assessed: false },
    expected: {
      enforcement_level: "not_yet_assessed",
      evidence_status: "not_yet_assessed",
      record_presence: "unknown",
      record_validity: "not_applicable",
      policy: null,
      pct: null,
      subdomain_policy: null,
      caveats: [],
      confidence: "low",
      last_observed: null,
    },
  },
  {
    name: "dns_unavailable",
    input: input(null, 0, { evidence_status: "unavailable" }),
    expected: {
      enforcement_level: "not_observed",
      evidence_status: "unavailable",
      record_presence: "unknown",
      record_validity: "not_applicable",
      policy: null,
      pct: null,
      subdomain_policy: null,
      caveats: [],
      confidence: "low",
      last_observed: OBSERVED_AT,
    },
  },
  {
    name: "no_record",
    input: input(null, 0),
    expected: {
      enforcement_level: "no_record",
      evidence_status: "observed",
      record_presence: "absent",
      record_validity: "not_applicable",
      policy: null,
      pct: null,
      subdomain_policy: null,
      caveats: [],
      confidence: "high",
      last_observed: OBSERVED_AT,
    },
  },
  {
    name: "multiple_records",
    input: input("v=DMARC1; p=reject; rua=mailto:dmarc@example.com", 2),
    expected: {
      enforcement_level: "invalid_record",
      record_presence: "present",
      record_validity: "invalid",
      invalid_reason: "multiple_records",
    },
  },
  {
    name: "not_dmarc1",
    input: input("v=DMARC2; p=reject", 1),
    expected: {
      enforcement_level: "invalid_record",
      record_presence: "present",
      record_validity: "invalid",
      invalid_reason: "not_dmarc1",
    },
  },
  {
    name: "missing_policy",
    input: input("v=DMARC1;", 1),
    expected: {
      enforcement_level: "invalid_record",
      record_presence: "present",
      record_validity: "invalid",
      invalid_reason: "unknown_policy_token",
    },
  },
  {
    name: "unknown_policy",
    input: input("v=DMARC1; p=future", 1),
    expected: {
      enforcement_level: "invalid_record",
      record_presence: "present",
      record_validity: "invalid",
      invalid_reason: "unknown_policy_token",
    },
  },
  {
    name: "malformed_pct",
    input: input("v=DMARC1; p=reject; pct=abc", 1),
    expected: {
      enforcement_level: "invalid_record",
      record_presence: "present",
      record_validity: "invalid",
      invalid_reason: "malformed_pct",
    },
  },
  {
    name: "unknown_subdomain_policy",
    input: input("v=DMARC1; p=reject; sp=future", 1),
    expected: {
      enforcement_level: "invalid_record",
      record_presence: "present",
      record_validity: "invalid",
      invalid_reason: "unknown_policy_token",
      subdomain_policy: null,
    },
  },
  {
    name: "monitoring",
    input: input("v=DMARC1; p=none; rua=mailto:dmarc@example.com", 1),
    expected: {
      enforcement_level: "monitoring",
      record_presence: "present",
      record_validity: "valid",
      policy: "none",
      pct: 100,
      subdomain_policy: "inherit",
      caveats: [],
      confidence: "high",
    },
  },
  {
    name: "quarantine_pct_zero",
    input: input("v=DMARC1; p=quarantine; pct=0; rua=mailto:dmarc@example.com", 1),
    expected: {
      enforcement_level: "partial_quarantine",
      policy: "quarantine",
      pct: 0,
      subdomain_policy: "inherit",
      caveats: ["policy_applies_to_zero_percent"],
    },
  },
  {
    name: "quarantine_partial",
    input: input("v=DMARC1; p=quarantine; pct=50; rua=mailto:dmarc@example.com", 1),
    expected: {
      enforcement_level: "partial_quarantine",
      policy: "quarantine",
      pct: 50,
      caveats: ["pct_below_100"],
    },
  },
  {
    name: "quarantine_full",
    input: input("v=DMARC1; p=quarantine; pct=100; rua=mailto:dmarc@example.com", 1),
    expected: {
      enforcement_level: "quarantine_enforced",
      policy: "quarantine",
      pct: 100,
      caveats: [],
    },
  },
  {
    name: "reject_pct_zero",
    input: input("v=DMARC1; p=reject; pct=0; rua=mailto:dmarc@example.com", 1),
    expected: {
      enforcement_level: "partial_reject",
      policy: "reject",
      pct: 0,
      caveats: ["policy_applies_to_zero_percent"],
    },
  },
  {
    name: "reject_partial",
    input: input("v=DMARC1; p=reject; pct=50; rua=mailto:dmarc@example.com", 1),
    expected: {
      enforcement_level: "partial_reject",
      policy: "reject",
      pct: 50,
      caveats: ["pct_below_100"],
    },
  },
  {
    name: "reject_full",
    input: input("v=DMARC1; p=reject; pct=100; rua=mailto:dmarc@example.com", 1),
    expected: {
      enforcement_level: "reject_enforced",
      policy: "reject",
      pct: 100,
      caveats: [],
    },
  },
  {
    name: "inherited_subdomain_policy",
    input: input("v=DMARC1; p=reject; rua=mailto:dmarc@example.com", 1),
    expected: {
      enforcement_level: "reject_enforced",
      policy: "reject",
      pct: 100,
      subdomain_policy: "inherit",
      caveats: [],
    },
  },
  {
    name: "reject_sp_none",
    input: input("v=DMARC1; p=reject; sp=none; rua=mailto:dmarc@example.com", 1),
    expected: {
      enforcement_level: "partial_reject",
      policy: "reject",
      pct: 100,
      subdomain_policy: "none",
      caveats: ["subdomain_gap"],
    },
  },
  {
    name: "reject_zero_sp_none",
    input: input("v=DMARC1; p=reject; pct=0; sp=none; rua=mailto:dmarc@example.com", 1),
    expected: {
      enforcement_level: "partial_reject",
      policy: "reject",
      pct: 0,
      subdomain_policy: "none",
      caveats: ["policy_applies_to_zero_percent", "subdomain_gap"],
    },
  },
  {
    name: "quarantine_partial_sp_none",
    input: input("v=DMARC1; p=quarantine; pct=50; sp=none; rua=mailto:dmarc@example.com", 1),
    expected: {
      enforcement_level: "partial_quarantine",
      policy: "quarantine",
      pct: 50,
      subdomain_policy: "none",
      caveats: ["subdomain_gap", "pct_below_100"],
    },
  },
];

function hasAllRequiredFields(state) {
  return REQUIRED_FIELDS.every((field) => Object.prototype.hasOwnProperty.call(state, field));
}

function arraysEqual(a, b) {
  return Array.isArray(a) && Array.isArray(b) && a.length === b.length && a.every((value, index) => value === b[index]);
}

function compareFixture(deriveDmarcState, fixture) {
  const state = deriveDmarcState(fixture.input);
  if (!hasAllRequiredFields(state)) return `${fixture.name}_missing_required_field`;
  if (state.state_model_version !== "2026-07-18") return `${fixture.name}_wrong_version`;
  if (!CANONICAL_LEVELS.includes(state.enforcement_level)) return `${fixture.name}_unknown_level`;
  if (!arraysEqual(state.caveats, [...state.caveats].sort((a, b) => CANONICAL_CAVEAT_ORDER.indexOf(a) - CANONICAL_CAVEAT_ORDER.indexOf(b)))) {
    return `${fixture.name}_wrong_caveat_order`;
  }
  for (const [key, expected] of Object.entries(fixture.expected)) {
    if (Array.isArray(expected)) {
      if (!arraysEqual(state[key], expected)) return `${fixture.name}_mismatch`;
    } else if (state[key] !== expected) {
      return `${fixture.name}_mismatch`;
    }
  }
  return null;
}

async function contract(mod) {
  const { deriveDmarcState, DMARC_STATE_MODEL_VERSION, DMARC_ENFORCEMENT_LEVELS, DMARC_CAVEAT_PRIORITY } = mod;
  if (typeof deriveDmarcState !== "function") return "derive_function_missing";
  if (DMARC_STATE_MODEL_VERSION !== "2026-07-18") return "state_model_version_wrong";
  if (!arraysEqual(DMARC_ENFORCEMENT_LEVELS, CANONICAL_LEVELS)) return "canonical_levels_wrong";
  if (!arraysEqual(DMARC_CAVEAT_PRIORITY, CANONICAL_CAVEAT_ORDER)) return "canonical_caveat_order_wrong";

  for (const fixture of fixtures) {
    const reason = compareFixture(deriveDmarcState, fixture);
    if (reason) return reason;
  }

  const source = deriveDmarcState.toString();
  if (/email-scan|computeScore|business-risk|cyber-mot|posture-events|api|frontend/i.test(source)) {
    return "pure_derivation_scope_leaked";
  }

  return null;
}

const baseline = await contract(realState);
eq("ADR-003 canonical DMARC state contract passes on real source", baseline, null);

if (!process.argv.includes("--no-mutate")) {
  const original = fs.readFileSync(statePath, "utf8");
  const mutations = [
    {
      name: "unavailable collapsed into missing",
      from: "  if (isUnavailableSignal(observationSignal)) {",
      to: "  if (false && isUnavailableSignal(observationSignal)) {",
      expected: "dns_unavailable_mismatch",
    },
    {
      name: "quarantine/reject state collapse",
      from: "    enforcementLevel = ordered.length === 0 ? \"reject_enforced\" : \"partial_reject\";",
      to: "    enforcementLevel = ordered.length === 0 ? \"quarantine_enforced\" : \"partial_quarantine\";",
      expected: "reject_pct_zero_mismatch",
    },
    {
      name: "partial/full collapse",
      from: "    enforcementLevel = ordered.length === 0 ? \"quarantine_enforced\" : \"partial_quarantine\";",
      to: "    enforcementLevel = \"quarantine_enforced\";",
      expected: "quarantine_pct_zero_mismatch",
    },
    {
      name: "missing/invalid collapse",
      from: "      enforcement_level: \"invalid_record\",",
      to: "      enforcement_level: \"no_record\",",
      expected: "multiple_records_mismatch",
    },
    {
      name: "wrong pct zero boundary",
      from: "  if (enforcing && pct > 0 && pct < 100) caveats.push(\"pct_below_100\");",
      to: "  if (enforcing && pct >= 0 && pct < 100) caveats.push(\"pct_below_100\");",
      expected: "quarantine_pct_zero_mismatch",
    },
    {
      name: "ignored subdomain gaps",
      from: "  if (enforcing && subdomainPolicy === \"none\") caveats.push(\"subdomain_gap\");",
      to: "  if (enforcing && subdomainPolicy === \"__never__\") caveats.push(\"subdomain_gap\");",
      expected: "reject_sp_none_mismatch",
    },
    {
      name: "wrong caveat order",
      from: "  \"policy_applies_to_zero_percent\",\n  \"subdomain_gap\",\n  \"pct_below_100\",",
      to: "  \"pct_below_100\",\n  \"subdomain_gap\",\n  \"policy_applies_to_zero_percent\",",
      expected: "canonical_caveat_order_wrong",
    },
    {
      name: "multiple caveats suppressed",
      from: "  return DMARC_CAVEAT_PRIORITY.filter((caveat) => present.has(caveat));",
      to: "  return DMARC_CAVEAT_PRIORITY.filter((caveat) => present.has(caveat)).slice(0, 1);",
      expected: "reject_zero_sp_none_mismatch",
    },
    {
      name: "reject_enforced awarded incorrectly",
      from: "      enforcement_level: \"no_record\",",
      to: "      enforcement_level: \"reject_enforced\",",
      expected: "no_record_mismatch",
    },
  ];

  let mutationFailures = 0;
  const engineDir = path.dirname(statePath);
  for (const m of mutations) {
    if (!original.includes(m.from)) {
      console.log(`FAIL mutation anchor missing: ${m.name}`);
      mutationFailures++;
      continue;
    }
    const mutantPath = path.join(engineDir, `dmarc-state.__mutant_${Math.random().toString(36).slice(2)}__.mjs`);
    fs.writeFileSync(mutantPath, original.replace(m.from, m.to));
    let reason;
    try {
      const mutant = await import(pathToFileURL(mutantPath).href + `?m=${encodeURIComponent(m.name)}`);
      reason = await contract(mutant);
    } finally {
      fs.rmSync(mutantPath, { force: true });
    }
    if (reason !== m.expected) {
      console.log(`FAIL mutation NOT caught as intended: ${m.name} -- got ${reason || "survived"}`);
      mutationFailures++;
    } else {
      console.log(`  mutation CAUGHT: ${m.name} (${reason})`);
    }
  }
  ok("ADR-003 canonical DMARC state mutations fail for intended reasons", mutationFailures === 0);
}

console.log(`\nDMARC canonical state: ${pass}/${pass + fail} passed`);
if (fail) { console.error("dmarc-canonical-state validation FAILED"); process.exit(1); }
console.log("dmarc-canonical-state validation passed");
