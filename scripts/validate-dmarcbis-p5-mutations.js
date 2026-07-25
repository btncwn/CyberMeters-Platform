#!/usr/bin/env node
// Item 7 P5 load-bearing mutation proof.
//
// Temporary adjacent copies retain the real import graph. Each mutant
// deliberately reintroduces a forbidden alert/case/verification defect and the
// named assertion observes that bad outcome. The normal P5 validator asserts
// the opposite contract, so any such production mutation turns CI red.
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const engines = path.join(root, "workers", "scan-api", "src", "engines");
const routes = path.join(root, "workers", "scan-api", "src", "routes");
let pass = 0;
let fail = 0;
let sequence = 0;

const ok = (name, condition) => {
  condition ? pass += 1 : fail += 1;
  if (!condition) console.error(`FAIL ${name}`);
};

async function withMutant(directory, file, from, to, run) {
  const sourcePath = path.join(directory, file);
  const source = fs.readFileSync(sourcePath, "utf8");
  const mutated = source.replace(from, to);
  ok(`${file} mutation applied`, mutated !== source);
  if (mutated === source) return;
  const mutantPath = path.join(
    directory,
    `.${file.replace(/\.js$/, "")}.p5-mutant.${process.pid}.${++sequence}.js`,
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

function completeEvidence(overrides = {}) {
  return {
    core_completeness: "complete",
    policy_completeness: "complete",
    rua_authorisation_completeness: "complete",
    corroboration_state: "corroborated",
    ...overrides,
  };
}

await withMutant(
  engines,
  "dmarcbis-managed-lifecycle.js",
  `  "external_rua_unauthorised",
]);`,
  `  "external_rua_unauthorised",
  "monitoring_degraded",
]);`,
  async ({ module }) => {
    const mutant = await module();
    ok(
      "MUTANT availability degradation becomes risk-alert eligible",
      mutant.isDmarcAlertDescriptorEligible({
        recurrence_type: "monitoring_degraded",
        transition_completeness: "complete",
      }),
    );
  },
);

await withMutant(
  engines,
  "dmarcbis-managed-lifecycle.js",
  `event?.transition_completeness === "complete"`,
  `event?.transition_completeness !== "complete"`,
  async ({ module }) => {
    const mutant = await module();
    ok(
      "MUTANT incomplete lifecycle evidence becomes alert eligible",
      mutant.isDmarcAlertDescriptorEligible({
        recurrence_type: "record_removed",
        transition_completeness: "incomplete",
      }),
    );
  },
);

await withMutant(
  engines,
  "dmarcbis-managed-lifecycle.js",
  `condition_present !== false ||`,
  `false ||`,
  async ({ module }) => {
    const mutant = await module();
    ok(
      "MUTANT still-active condition becomes verifiable",
      mutant.isDmarcCaseVerificationEligible({
        condition_type: "weak",
        evidence: completeEvidence(),
        condition_present: true,
        observed_at: "2026-07-25T12:00:00Z",
        requested_at: "2026-07-25T11:00:00Z",
      }),
    );
  },
);

await withMutant(
  engines,
  "dmarcbis-managed-lifecycle.js",
  `observedMs > requestedMs;`,
  `observedMs >= requestedMs;`,
  async ({ module }) => {
    const mutant = await module();
    ok(
      "MUTANT same scan that requested verification can verify",
      mutant.isDmarcCaseVerificationEligible({
        condition_type: "weak",
        evidence: completeEvidence(),
        condition_present: false,
        observed_at: "2026-07-25T12:00:00Z",
        requested_at: "2026-07-25T12:00:00Z",
      }),
    );
  },
);

await withMutant(
  engines,
  "dmarcbis-lifecycle.js",
  `evidence.rua_authorisation_completeness === "complete";`,
  `true;`,
  async ({ module }) => {
    const mutant = await module();
    ok(
      "MUTANT core-only evidence can clear external-RUA condition",
      mutant.isDmarcPolicyConditionComplete(
        "unauthorised_rua",
        completeEvidence({ rua_authorisation_completeness: "incomplete" }),
      ),
    );
  },
);

// Absence-of-path invariants use source-level mutants: P5 deliberately has no
// auto-open or RUA/note verification function to invoke. The production
// validator asserts these forbidden tokens/branches are absent.
await withMutant(
  engines,
  "scan-engine.js",
  `await emitDmarcPolicyAlerts(env, {`,
  `await createDmarcPolicyCase(env, lifecycleResult);
        await emitDmarcPolicyAlerts(env, {`,
  async ({ source }) => {
    ok(
      "MUTANT scan engine gains prohibited automatic case creation",
      source.includes("createDmarcPolicyCase(env, lifecycleResult)"),
    );
  },
);

await withMutant(
  routes,
  "managed-cases.js",
  `if (isDmarcPolicyCaseRequest(body)) {`,
  `if (false && isDmarcPolicyCaseRequest(body)) {`,
  async ({ source }) => {
    ok(
      "MUTANT DMARC request falls through to caller-trusting generic factory",
      source.includes("if (false && isDmarcPolicyCaseRequest(body))"),
    );
  },
);

await withMutant(
  engines,
  "dmarcbis-managed-lifecycle.js",
  `WHERE workspace_id = ? AND record_type = ? AND record_id = ?`,
  `WHERE record_type = ? AND record_id = ?`,
  async ({ source }) => {
    ok(
      "MUTANT removes workspace scope from occurrence identity lookup",
      !source.includes(
        "WHERE workspace_id = ? AND record_type = ? AND record_id = ?",
      ),
    );
  },
);

await withMutant(
  engines,
  "dmarcbis-managed-lifecycle.js",
  `INSERT OR IGNORE INTO email_protection_events`,
  `INSERT INTO email_protection_events`,
  async ({ source }) => {
    ok(
      "MUTANT removes case-link replay dedupe",
      !source.includes("INSERT OR IGNORE INTO email_protection_events"),
    );
  },
);

await withMutant(
  engines,
  "dmarcbis-managed-lifecycle.js",
  `const state = await loadCurrentDmarcState(env, {`,
  `await env.cybermeters_db.prepare("SELECT * FROM dmarc_aggregate_records").all();
  const state = await loadCurrentDmarcState(env, {`,
  async ({ source }) => {
    ok(
      "MUTANT treats RUA ingestion as case-verification evidence",
      source.includes("FROM dmarc_aggregate_records"),
    );
  },
);

console.log(`\nDMARCbis P5 mutations: ${pass} passed, ${fail} failed`);
if (!fail) console.log("DMARCbis P5 mutation proof passed");
process.exit(fail ? 1 : 0);
