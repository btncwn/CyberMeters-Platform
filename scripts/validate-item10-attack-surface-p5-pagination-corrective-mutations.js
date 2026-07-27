#!/usr/bin/env node
// Item 10 P5 corrective — load-bearing route-wiring mutation proof.
import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const routes = path.join(root, "workers/scan-api/src/routes");
const routeFile = path.join(routes, "attack-surface.js");
const validator = path.join(
  root,
  "scripts/validate-item10-attack-surface-p5-pagination-corrective.js",
);
const source = fs.readFileSync(routeFile, "utf8");
const EXPECTED_MUTANTS = 4;
const EXPECTED_ASSERTIONS = 9;
let mutantsKilled = 0;
let mutantFailures = 0;
let assertionsPassed = 0;
let assertionFailures = 0;
let sequence = 0;

function assert(name, condition, detail = "") {
  if (condition) assertionsPassed += 1;
  else {
    assertionFailures += 1;
    console.error(`FAIL ${name}${detail ? ` — ${detail}` : ""}`);
  }
}

function replaceRequired(input, from, to, label) {
  const mutated = input.replace(from, to);
  assert(`${label}: anchor guard`, mutated !== input, "mutated === original");
  return mutated;
}

function replaceLastRequired(input, from, to, label) {
  const index = input.lastIndexOf(from);
  const mutated = index < 0
    ? input
    : `${input.slice(0, index)}${to}${input.slice(index + from.length)}`;
  assert(`${label}: anchor guard`, mutated !== input, "mutated === original");
  return mutated;
}

function runMutant(name, mutate) {
  sequence += 1;
  const mutantName =
    `.attack-surface.item10-p5-corrective-mutant.${process.pid}.${sequence}.js`;
  const mutantFile = path.join(routes, mutantName);
  const mutated = mutate(source);
  fs.writeFileSync(mutantFile, mutated);
  try {
    const child = spawnSync(process.execPath, [validator], {
      cwd: root,
      encoding: "utf8",
      env: {
        ...process.env,
        ITEM10_P5_CORRECTIVE_ROUTE_MODULE_URL:
          pathToFileURL(mutantFile).href,
      },
    });
    const killed = child.status !== 0;
    assert(
      `${name}: suite turns red`,
      killed,
      killed ? "" : "validator exited zero",
    );
    if (killed) mutantsKilled += 1;
    else {
      mutantFailures += 1;
      console.error(`FAIL ${name}: mutant survived`);
    }
  } finally {
    fs.rmSync(mutantFile, { force: true });
  }
}

runMutant("re-couple domain lifecycle to paginated list rows", (input) =>
  replaceLastRequired(
    input,
    `          const assurance = await loadWorkspaceAttackSurfacePresentations(
            env,
            wsId,
          );`,
    `          const pageEvidence =
            await loadAttackSurfacePresentationEvidence(env, wsId);
          const pageContext = presentationContext(
            result.rows,
            result.lifecycle_available,
            pageEvidence,
          );
          const assurance = {
            domains: pageContext.domains,
            coverage: lifecycleEvidenceCoverage({
              returned: result.rows.length,
              total: result.rows.length,
              bound: limit,
              lifecycleAvailable: result.lifecycle_available,
            }),
            forAsset: pageContext.forAsset,
          };`,
    "independent list presentation read",
  ));

runMutant("re-add full presentation to every asset row", (input) =>
  replaceRequired(
    input,
    `            assets: result.rows,`,
    `            assets: result.rows.map((asset) => ({
              ...asset,
              attack_surface_assurance: assurance.domains.find(
                (projection) => projection.domain_id === asset.domain_id,
              ),
            })),`,
    "list response de-duplication",
  ));

runMutant("drop lifecycle coverage metadata", (input) =>
  replaceLastRequired(
    input,
    `            attack_surface_assurance_coverage: assurance.coverage,`,
    ``,
    "list coverage metadata",
  ));

runMutant("silently read fewer lifecycle rows than the declared bound", (input) => {
  const smallerRead = replaceRequired(
    input,
    `      .bind(workspaceId, bound)`,
    `      .bind(workspaceId, Math.max(1, bound - 1))`,
    "lifecycle SQL bound",
  );
  return replaceRequired(
    smallerRead,
    `        returned: result.rows.length,`,
    `        returned: Math.min(result.total, bound),`,
    "lifecycle returned-row metadata",
  );
});

console.log(
  `Item 10 P5 pagination corrective mutations: ` +
  `${mutantsKilled}/${EXPECTED_MUTANTS} mutants killed; ` +
  `${assertionsPassed}/${EXPECTED_ASSERTIONS} assertions passed`,
);
if (
  mutantsKilled !== EXPECTED_MUTANTS ||
  mutantFailures > 0 ||
  assertionsPassed !== EXPECTED_ASSERTIONS ||
  assertionFailures > 0
) process.exit(1);
