#!/usr/bin/env node
// Item 10 P3 — load-bearing source mutation proof.
import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const engines = path.join(root, "workers/scan-api/src/engines");
const validator = path.join(
  root, "scripts/validate-item10-attack-surface-p3-lifecycle-cases.js",
);
const paths = {
  cases: path.join(engines, "asm-cases.js"),
  lifecycle: path.join(engines, "attack-surface-lifecycle.js"),
  signal: path.join(engines, "attack-surface-signal-completeness.js"),
};
const sources = Object.fromEntries(Object.entries(paths).map(([key, file]) => [
  key,
  fs.readFileSync(file, "utf8"),
]));
let passed = 0;
let failed = 0;
let sequence = 0;

function result(name, killed, detail = "") {
  if (killed) passed += 1;
  else {
    failed += 1;
    console.error(`FAIL ${name}: mutant survived${detail ? ` — ${detail}` : ""}`);
  }
}

function mutateRequired(source, from, to, label) {
  const next = typeof from === "string"
    ? source.replace(from, to)
    : source.replace(from, to);
  if (next === source) throw new Error(`mutation anchor missing: ${label}`);
  return next;
}

function runMutant(name, {
  mutateCases = (source) => source,
  mutateLifecycle = (source) => source,
  mutateSignal = (source) => source,
} = {}) {
  sequence += 1;
  const names = {
    signal: `.attack-surface-signal-completeness.item10-p3-mutant.${process.pid}.${sequence}.js`,
    lifecycle: `.attack-surface-lifecycle.item10-p3-mutant.${process.pid}.${sequence}.js`,
    cases: `.asm-cases.item10-p3-mutant.${process.pid}.${sequence}.js`,
  };
  const files = Object.fromEntries(Object.entries(names).map(([key, file]) => [
    key,
    path.join(engines, file),
  ]));
  let signal = mutateSignal(sources.signal);
  let lifecycle = mutateLifecycle(sources.lifecycle).replace(
    '"./attack-surface-signal-completeness.js"',
    `"./${names.signal}"`,
  );
  const cases = mutateCases(sources.cases);
  const changed =
    signal !== sources.signal ||
    lifecycle.replace(`"./${names.signal}"`, '"./attack-surface-signal-completeness.js"') !== sources.lifecycle ||
    cases !== sources.cases;
  if (!changed) {
    result(name, false, "no source changed");
    return;
  }
  fs.writeFileSync(files.signal, signal);
  fs.writeFileSync(files.lifecycle, lifecycle);
  fs.writeFileSync(files.cases, cases);
  try {
    const child = spawnSync(process.execPath, [validator], {
      cwd: root,
      encoding: "utf8",
      env: {
        ...process.env,
        ITEM10_P3_SIGNAL_MODULE_URL: pathToFileURL(files.signal).href,
        ITEM10_P3_LIFECYCLE_MODULE_URL: pathToFileURL(files.lifecycle).href,
        ITEM10_P3_CASES_MODULE_URL: pathToFileURL(files.cases).href,
      },
    });
    result(name, child.status !== 0);
  } finally {
    for (const file of Object.values(files)) fs.rmSync(file, { force: true });
  }
}

runMutant("first removal closes case", {
  mutateCases: (source) => mutateRequired(
    source,
    "Date.parse(row.observed_at) <= Date.parse(row.confirmed_removed_at)",
    "Date.parse(row.observed_at) < Date.parse(row.confirmed_removed_at)",
    "later re-observation strictness",
  ),
});

runMutant("unavailable closes case", {
  mutateSignal: (source) => mutateRequired(
    mutateRequired(
      source,
      "rows.length >= policy.required_qualifying_observations &&",
      "rows.length >= 1 &&",
      "one-scan threshold",
    ),
    "windowMs >= policy.minimum_confirmation_window_ms;",
    "windowMs >= 0;",
    "confirmation window",
  ),
  mutateLifecycle: (source) => mutateRequired(
    mutateRequired(
      source,
      "dns_resolution: row?.signal_states?.dns_resolution || notAssessedSignals().dns_resolution,",
      "dns_resolution: { state: \"absent\", reason: \"mutant_unavailable_as_absent\" },",
      "unavailable DNS coercion",
    ),
    "http_https_service: row?.signal_states?.http_https_service || notAssessedSignals().http_https_service,",
    "http_https_service: { state: \"not_observed\", reason: \"mutant_unavailable_as_absent\" },",
    "unavailable HTTP coercion",
  ),
  mutateCases: (source) => mutateRequired(
    source,
    "if (scanPartial) return false;",
    "if (scanPartial) return true;",
    "partial scan verification gate",
  ),
});

runMutant("customer assertion verifies", {
  mutateCases: (source) => mutateRequired(
    source,
    /export async function transitionManagedCase\(env, caseRow, to, ctx = \{\}\) \{[\s\S]*?\n\}/,
    `export async function transitionManagedCase(env, caseRow, to, ctx = {}) {
  if (to === "resolved" && (ctx.actor_type || "customer") !== "system") {
    const verifying = await updateCaseStatus(env, caseRow, "verifying", {
      actor_type: "system",
      action: "verification_started",
    });
    if (!verifying.ok) return verifying;
    return updateCaseStatus(env, verifying.case, to, {
      actor_type: "system",
      action: "verified_resolved",
      evidence: {
        outcome: "resolved",
        evidence_type: "automated_recheck",
        verification_method: "laundered_customer_assertion",
        verification_support: "supported",
      },
    });
  }
  return updateCaseStatus(env, caseRow, to, ctx);
}`,
    "customer verification actor/state laundering",
  ),
});

runMutant("reappeared creates a new asset identity", {
  mutateLifecycle: (source) => mutateRequired(
    source,
    '} else if (result.transition === "reappeared") {\n        const eventId = await deterministicAssetEventId(',
    `} else if (result.transition === "reappeared") {
        statements.push(
          env.cybermeters_db
            .prepare("UPDATE workspace_assets SET id = ? WHERE id = ? AND workspace_id = ?")
            .bind(createId("asset"), asset.id, workspaceId)
        );
        const eventId = await deterministicAssetEventId(`,
    "reappearance identity rewrite",
  ),
});

runMutant("DNS-only becomes absent", {
  mutateSignal: (source) => mutateRequired(
    source,
    'if (states.some((state) => state === "observed")) return "observed";',
    'if (states[0] === "observed" && states[1] !== "observed") return "not_observed";\n  if (states.some((state) => state === "observed")) return "observed";',
    "DNS-only absence coercion",
  ),
});

runMutant("direct case transition bypass", {
  mutateCases: (source) => mutateRequired(
    source,
    /  const result = canTransitionCase\(\{\n    case: caseRow, target_status: to,[\s\S]*?\n  \}\);\n  if \(!result\.ok\) return result;/,
    `  const result = {
    ok: true,
    case: { ...caseRow, status: to, updated_at: ctx.now || new Date().toISOString() },
  };`,
    "canonical transition validator",
  ),
});

runMutant("repeated scan duplicates event/case", {
  mutateCases: (source) => mutateRequired(
    mutateRequired(
      source,
      "if (existing) {",
      "if (false && existing) {",
      "existing ASM case reuse",
    ),
    "source_finding_id: finding.id,",
    'source_finding_id: `${finding.id}:${scanId}:${Math.random()}`,',
    "stable case identity",
  ),
});

console.log(`\nItem 10 P3 mutations: ${passed}/${passed + failed} killed`);
if (failed) process.exit(1);
console.log("Item 10 P3 mutation validation passed");
