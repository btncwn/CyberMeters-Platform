#!/usr/bin/env node
// Item 7 P4 load-bearing mutation proof.
//
// Temporary adjacent copies retain the real import graph. Each mutant
// deliberately reintroduces a forbidden lifecycle/correlation defect and the
// named fixture observes that bad outcome (therefore the normal suite would
// turn red if the mutation entered production).
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const engines = path.join(root, "workers", "scan-api", "src", "engines");
let pass = 0;
let fail = 0;
let sequence = 0;

const ok = (name, condition) => {
  condition ? pass += 1 : fail += 1;
  if (!condition) console.error(`FAIL ${name}`);
};

async function withMutant(file, from, to, run) {
  const sourcePath = path.join(engines, file);
  const source = fs.readFileSync(sourcePath, "utf8");
  const mutated = source.replace(from, to);
  ok(`${file} mutation applied`, mutated !== source);
  if (mutated === source) return;
  const mutantPath = path.join(
    engines,
    `.${file.replace(/\.js$/, "")}.p4-mutant.${process.pid}.${++sequence}.js`,
  );
  fs.writeFileSync(mutantPath, mutated);
  try {
    const module = await import(
      `${pathToFileURL(mutantPath).href}?mutation=${sequence}`,
    );
    await run(module);
  } finally {
    fs.rmSync(mutantPath, { force: true });
  }
}

function evidence(overrides = {}) {
  return {
    author_domain: "example.test",
    observation_state: "present_valid",
    record_validity: "valid",
    lookup_path: [],
    organisational_domain: "example.test",
    organisational_domain_completeness: "complete",
    policy_source_domain: "example.test",
    policy_source_kind: "exact",
    domain_existence: "not_required",
    existence_completeness: "not_applicable",
    declared_policy: "reject",
    effective_requested_policy: "reject",
    effective_policy_tag: "p",
    inheritance_reason: "exact_p",
    testing_adjustment: "none",
    p: { normalized: "reject" },
    sp: null,
    np: null,
    t: null,
    legacy_pct: {
      observed: false,
      raw: null,
      applied_to_effective_policy: false,
    },
    rua_destinations: [],
    external_rua_authorisation: { destinations: [] },
    core_completeness: "complete",
    policy_completeness: "complete",
    organisational_domain_completeness: "complete",
    rua_authorisation_completeness: "not_applicable",
    corroboration_state: "corroborated",
    monitoring_state: "monitoring_healthy",
    provider_state: "available",
    ...overrides,
  };
}

await withMutant(
  "dmarcbis-lifecycle.js",
  `function exactComplete(evidence) {
  return coreComplete(evidence) &&`,
  `function exactComplete(evidence) {
  return true ||`,
  async (mutant) => {
    const transitions = mutant.deriveDmarcPolicyTransitions(
      evidence(),
      evidence({
        observation_state: "absent",
        record_validity: "indeterminate",
        core_completeness: "unavailable",
        policy_completeness: "unavailable",
        monitoring_state: "monitoring_degraded",
        provider_state: "timeout",
      }),
    );
    ok(
      "MUTANT incomplete current evidence becomes false record removal",
      transitions.some((item) => item.subtype === "record_removed"),
    );
  },
);

await withMutant(
  "dmarcbis-lifecycle-contract.js",
  `  "monitoring_degraded",
]);`,
  `  "monitoring_degraded",
  "monitoring_recovered",
]);`,
  async (mutant) => {
    ok(
      "MUTANT prohibited monitoring_recovered enters stable taxonomy",
      mutant.DMARC_LIFECYCLE_SUBTYPES.includes("monitoring_recovered"),
    );
  },
);

await withMutant(
  "dmarcbis-lifecycle.js",
  `    afterSnapshotId,
    beforeFingerprint,`,
  `    beforeFingerprint,`,
  async (mutant) => {
    const common = {
      workspaceId: "ws",
      domainId: "dom",
      methodologyVersion: "rfc9989-treewalk-v1",
      subtype: "policy_changed",
      subjectKey: "example.test",
      beforeSnapshotId: "snap-before",
      beforeFingerprint: "a",
      afterFingerprint: "b",
    };
    const first = mutant.dmarcLifecycleEventIdentity({
      ...common,
      afterSnapshotId: "snap-current-1",
    });
    const recurrence = mutant.dmarcLifecycleEventIdentity({
      ...common,
      afterSnapshotId: "snap-current-2",
    });
    ok(
      "MUTANT removing current snapshot collapses distinct occurrences",
      first === recurrence,
    );
  },
);

await withMutant(
  "posture-events.js",
  "if (!hasCanonicalDmarcbis) {",
  "if (true) {",
  async (mutant) => {
    const before = {
      dmarc_core: { schema: "dmarc-policy.v2" },
      email_security: { dmarc: { present: true, policy: "none" } },
    };
    const after = {
      dmarc_core: { schema: "dmarc-policy.v2" },
      email_security: { dmarc: { present: true, policy: "reject" } },
    };
    const events = mutant.buildPostureDiffEvents(
      "example.test",
      before,
      after,
    );
    ok(
      "MUTANT canonical scan also emits legacy coarse DMARC event",
      events.some((item) =>
        item.event_type === "email_dmarc_policy_changed"),
    );
  },
);

function adapterEnv(detail) {
  return {
    cybermeters_db: {
      prepare(sql) {
        const statement = {
          bind() { return statement; },
          async all() {
            if (sql.includes("FROM email_protection_events")) {
              return {
                results: [{
                  id: "epe-test",
                  event_type: "dmarc_policy_transition",
                  detail_json: JSON.stringify(detail),
                  created_at: "2026-07-25T12:00:00.000Z",
                }],
              };
            }
            return { results: [] };
          },
        };
        return statement;
      },
    },
  };
}

await withMutant(
  "related-changes-adapter.js",
  "producer_family: SIGNAL_FAMILY.EMAIL_CONFIG,",
  'producer_family: "dmarc",',
  async (mutant) => {
    const events = await mutant.collectChangeEvents(adapterEnv({
      subtype: "policy_changed",
      related_changes_eligible: true,
      transition_completeness: "complete",
      author_domain: "example.test",
      after_snapshot_id: "snap-after",
    }), {
      workspaceId: "ws",
      windowStart: "2026-07-25T11:00:00.000Z",
      windowEnd: "2026-07-25T13:00:00.000Z",
    });
    ok(
      "MUTANT creates an independent DMARC signal family",
      events.some((item) => item.producer_family === "dmarc"),
    );
  },
);

await withMutant(
  "related-changes-adapter.js",
  'detail?.transition_completeness !== "complete"',
  "false",
  async (mutant) => {
    const events = await mutant.collectChangeEvents(adapterEnv({
      subtype: "policy_changed",
      related_changes_eligible: true,
      transition_completeness: "incomplete",
      author_domain: "example.test",
      after_snapshot_id: "snap-after",
    }), {
      workspaceId: "ws",
      windowStart: "2026-07-25T11:00:00.000Z",
      windowEnd: "2026-07-25T13:00:00.000Z",
    });
    ok(
      "MUTANT incomplete DMARC event enters Related Changes",
      events.some((item) =>
        item.source_table === "email_protection_events"),
    );
  },
);

await withMutant(
  "dmarcbis-lifecycle.js",
  'return String(\n    uri?.normalized_uri || uri?.uri || uri?.raw || uri?.raw_uri || "",\n  ).trim();',
  'return String(\n    uri?.normalized_uri || uri?.uri || uri?.raw || uri?.raw_uri || "",\n  ).trim().toLowerCase();',
  async (mutant) => {
    const destination = (uri) => ({
      author_domain: "example.test",
      observation_state: "present_valid",
      record_validity: "valid",
      core_completeness: "complete",
      policy_completeness: "complete",
      organisational_domain_completeness: "complete",
      existence_completeness: "complete",
      corroboration_state: "confirmed",
      policy_source_domain: "example.test",
      policy_source_kind: "exact",
      effective_requested_policy: "reject",
      declared_policy: "reject",
      effective_policy_tag: "p",
      p: { normalized: "reject" },
      rua_authorisation_completeness: "complete",
      monitoring_state: "complete",
      provider_state: "available",
      rua_destinations: [{
        normalized_uri: uri,
        syntax_valid: true,
        supported_scheme: true,
      }],
      external_rua_authorisation: {
        destinations: [{
          normalized_uri: uri,
          authorization_status: "authorized",
          same_organisational_domain: false,
          lookup_completeness: "complete",
        }],
      },
    });
    const events = mutant.deriveDmarcPolicyTransitions(
      destination("mailto:Reports@reports.vendor.test"),
      destination("mailto:reports@reports.vendor.test"),
    );
    ok(
      "MUTANT lowercases case-sensitive mailto lifecycle identity",
      !events.some((item) =>
        ["external_rua_added", "external_rua_removed"].includes(item.subtype)),
    );
  },
);

console.log(`\nDMARCbis P4 mutations: ${pass} passed, ${fail} failed`);
if (fail) process.exit(1);
console.log("DMARCbis P4 mutation validation passed");
