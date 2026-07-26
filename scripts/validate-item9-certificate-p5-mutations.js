#!/usr/bin/env node
// Item 9 P5 — load-bearing source mutation proof.
//
// Each mutant is a temporary copy of the real presentation engine. The checked
// invariant observes the reintroduced customer-surface defect. Checked-in
// source is never modified.
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const engines = path.join(root, "workers", "scan-api", "src", "engines");
let pass = 0;
let fail = 0;
let sequence = 0;

const ok = (name, condition, detail = "") => {
  condition ? pass++ : fail++;
  if (condition) console.log(`ok - ${name}`);
  else console.error(`not ok - ${name}${detail ? `: ${detail}` : ""}`);
};

async function withMutant(mutate, run) {
  const file = "certificate-customer-presentation.js";
  const sourcePath = path.join(engines, file);
  const source = fs.readFileSync(sourcePath, "utf8");
  const mutated = mutate(source);
  ok(`mutation ${sequence + 1} applied`, mutated !== source);
  if (mutated === source) return;
  const mutantPath = path.join(
    engines,
    `.certificate-customer-presentation.item9-p5-mutant.${process.pid}.${++sequence}.js`,
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

const provenance = {
  source: "fixture",
  method: "injected",
  observed_at: "2026-07-26T15:00:00.000Z",
  engine_version: "item9-p5-mutation",
};
const signal = ({
  observation = "present",
  completeness_state = "monitoring_healthy",
  value = {},
  observation_scope = "live_tls",
} = {}) => ({
  observation,
  completeness_state,
  value,
  observation_scope,
  achieved_grade: observation === "present" ? "L1" : "L0",
  publishable: observation === "present",
  grade_contract: {
    observable_ceiling: "L3",
    beta_target: "L1",
    minimum_publishable: "L1",
    degrade_behavior: "unknown",
    required_corroboration: ["fixture"],
  },
  source_type: "normative_protocol",
  provenance,
  authorities: [{
    standard_id: "RFC 5280",
    standard_version: "May 2008",
    section: "§4.1",
    requirement_type: "protocol_profile",
  }],
});
const model = (signals) => ({
  model_version: "certificate-signal-completeness-v2",
  signals,
  summary: { ct_only: false },
});

await withMutant(
  (source) => source.replace(
    `if (observation === "unknown") return "unknown";`,
    `if (observation === "unknown") return "observed";`,
  ),
  async (mutant) => {
    const result = mutant.buildCertificateCustomerPresentation({
      signalCompleteness: model({
        leaf: signal({ observation: "unknown", value: null }),
      }),
    });
    ok("MUTANT unknown becomes favourable observed and makes parity fixture red",
      result.signals.leaf.state === "observed");
  },
);

await withMutant(
  (source) => source.replace(
    `state: liveLeaf.state,
      message: ctOnly && liveLeaf.state !== "observed"`,
    `state: ctOnly ? "observed" : liveLeaf.state,
      message: ctOnly && liveLeaf.state !== "observed"`,
  ),
  async (mutant) => {
    const result = mutant.buildCertificateCustomerPresentation({
      signalCompleteness: {
        ...model({
          certificate_transparency: signal({
            observation_scope: "ct_issuance",
          }),
          leaf: signal({ observation: "unknown", value: null }),
        }),
        summary: { ct_only: true },
      },
    });
    ok("MUTANT CT-only becomes live-serving and makes parity fixture red",
      result.summary.live_tls_certificate.state === "observed");
  },
);

await withMutant(
  (source) => source.replace(
    `if (!presentInModel) return "not_observed";`,
    `if (!presentInModel) return "observed";`,
  ),
  async (mutant) => {
    const result = mutant.buildCertificateCustomerPresentation({
      signalCompleteness: model({
        leaf: signal(),
      }),
    });
    ok("MUTANT missing field becomes observed/passed and makes fixture red",
      result.signals.chain.state === "observed");
  },
);

await withMutant(
  (source) => source.replace(
    `? "replacement_with_parallel_transition_context"`,
    `? "replacement_lifecycle"`,
  ),
  async (mutant) => {
    const previous = model({
      leaf: signal({
        value: { certificate_identity: "sha256:previous" },
      }),
    });
    const current = model({
      leaf: signal({
        value: { certificate_identity: "sha256:current" },
      }),
      parallel_certificate_set: signal({
        observation_scope: "live_tls_endpoint_set",
        value: {
          observations: [
            { certificate_identity: "sha256:previous" },
            { certificate_identity: "sha256:current" },
          ],
        },
      }),
    });
    const result = mutant.buildCertificateRelationshipPresentation({
      lifecycle: {
        replacement_detected_at: "2026-07-26T15:00:00.000Z",
        certificate_identity: "sha256:current",
      },
      currentSignalCompleteness: current,
      previousSignalCompleteness: previous,
    });
    ok("MUTANT replacement/parallel loses unified precedence and makes fixture red",
      result.relationship === "replacement_lifecycle" &&
      result.parallel_live_set_observed === true);
  },
);

await withMutant(
  (source) => source.replace(
    `return buildCertificateCustomerPresentation({ absenceReason: reason });`,
    `return buildCertificateCustomerPresentation({
    signalCompleteness: {
      model_version: "certificate-signal-completeness-v2",
      signals: {},
      summary: { ct_only: false },
    },
    absenceReason: reason,
  });`,
  ),
  async (mutant) => {
    const legacy = mutant.certificateAssuranceFromSnapshot({
      snapshot: { snapshot_schema_version: "1" },
    });
    ok("MUTANT historical missing block is synthesised as current and makes fixture red",
      legacy.status === "current");
  },
);

await withMutant(
  (source) => source.replace(
    `provenance: raw?.provenance || null,`,
    `provenance: null,`,
  ),
  async (mutant) => {
    const result = mutant.buildCertificateCustomerPresentation({
      signalCompleteness: model({
        leaf: signal(),
      }),
    });
    ok("MUTANT evidence provenance is dropped and makes fidelity fixture red",
      result.signals.leaf.provenance === null);
  },
);

console.log(`\nItem 9 P5 mutations: ${pass} passed, ${fail} failed`);
if (fail) process.exit(1);
console.log("Item 9 P5 mutation validation passed");
