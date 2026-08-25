#!/usr/bin/env node
// Item 7 P6 load-bearing mutation proof. Each mutant reintroduces a renderer
// derivation, historical reinterpretation, false enforcement claim, or RUA
// overclaim that the normal P6 fixtures reject.
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
    `.${file.replace(/\.js$/, "")}.p6-mutant.${process.pid}.${++sequence}.js`,
  );
  fs.writeFileSync(mutantPath, mutated);
  try {
    await run({
      source: mutated,
      module: async () => import(
        `${pathToFileURL(mutantPath).href}?mutation=${sequence}`,
      ),
    });
  } finally {
    fs.rmSync(mutantPath, { force: true });
  }
}

function read(evidence = {}) {
  return {
    status: "current",
    evidence: {
      author_domain: "example.test",
      observation_state: "present_valid",
      record_validity: "valid",
      declared_policy: "reject",
      effective_requested_policy: "reject",
      policy_source_kind: "exact",
      policy_completeness: "complete",
      core_completeness: "complete",
      monitoring_state: "monitoring_healthy",
      receiver_enforcement_observed: false,
      legacy_pct: {
        observed: true,
        raw: "25",
        applied_to_effective_policy: false,
      },
      ...evidence,
    },
  };
}

await withMutant(
  "dmarcbis-presentation.js",
  "This does not prove every receiver applied that request.",
  "DMARC enforcement is proven for every receiver.",
  async ({ module }) => {
    const mutant = await module();
    const presentation = mutant.buildDmarcPolicyPresentation(read());
    ok("MUTANT introduces prohibited receiver-enforcement wording",
      presentation.policy.message.includes("DMARC enforcement is proven"));
  },
);

await withMutant(
  "dmarcbis-presentation.js",
  "applied_to_effective_policy: false,",
  "applied_to_effective_policy: true,",
  async ({ module }) => {
    const mutant = await module();
    ok("MUTANT silently reapplies legacy pct",
      mutant.buildDmarcPolicyPresentation(read())
        .legacy_pct.applied_to_effective_policy === true);
  },
);

await withMutant(
  "dmarcbis-presentation.js",
  "technical_appendix: null,",
  `technical_appendix: {
        facts: [{ label: "Recomputed policy", value: "reject" }],
      },`,
  async ({ module }) => {
    const mutant = await module();
    const legacy = mutant.buildDmarcPolicyPresentation({
      status: "legacy_snapshot",
      evidence: null,
      notice: "Historical notice",
    });
    ok("MUTANT manufactures current interpretation for legacy snapshot",
      legacy.technical_appendix?.facts?.[0]?.value === "reject");
  },
);

await withMutant(
  "dmarcbis-presentation.js",
  // Anchor re-derived for D3: the honest disclaimer sentence now also appears in
  // the CyberMeters-hosted destination message, and replace() takes the FIRST
  // occurrence — anchor on the full authorized-case sentence so the mutant hits
  // the message the fixture actually reads.
  "The external reporting destination published a valid DMARC authorisation record. This does not prove reports were sent, received, or trusted.",
  "The external reporting destination published a valid DMARC authorisation record. External reporting is working.",
  async ({ module }) => {
    const mutant = await module();
    const presentation = mutant.buildDmarcPolicyPresentation(read({
      external_rua_authorisation: {
        destinations: [{
          uri: "mailto:agg@vendor.test",
          authorization_status: "authorized",
        }],
      },
    }));
    ok("MUTANT authorisation becomes false report-delivery proof",
      presentation.external_rua.destinations[0].message.includes(
        "reporting is working",
      ));
  },
);

await withMutant(
  "dmarcbis-presentation.js",
  "return \"CyberMeters could not determine the current DMARC policy because a required DNS lookup was unavailable. This is not a missing-record result.\";",
  "return \"CyberMeters completed the lookup and found no DMARC record.\";",
  async ({ module }) => {
    const mutant = await module();
    const presentation = mutant.buildDmarcPolicyPresentation(read({
      observation_state: "unavailable",
      policy_completeness: "unavailable",
      core_completeness: "unavailable",
      effective_requested_policy: null,
    }));
    ok("MUTANT collapses unavailable into absent",
      presentation.customer_message.includes("found no DMARC record"));
  },
);

await withMutant(
  "dmarcbis-presentation.js",
  "receiver_enforcement_observed: false,",
  "receiver_enforcement_observed: true,",
  async ({ module }) => {
    const mutant = await module();
    ok("MUTANT presentation claims receiver enforcement",
      mutant.buildDmarcPolicyPresentation(read())
        .policy.receiver_enforcement_observed === true);
  },
);

console.log(`\nDMARCbis P6 mutations: ${pass} passed, ${fail} failed`);
if (!fail) console.log("DMARCbis P6 mutation proof passed");
process.exit(fail ? 1 : 0);
