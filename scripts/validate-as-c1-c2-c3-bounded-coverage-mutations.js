#!/usr/bin/env node
// AS-C1/C2/C3 U1+U2+U3 — registry-derived semantic mutation proof.
//
// Every mutant runs the focused oracle in a fresh Node process against a fresh
// source sandbox. Exact anchors/replacements, loaded-module SHA proof, ordered
// failure IDs, candidate target-byte restoration, and worktree restoration are
// all mandatory. Parser/import/runtime/setup failures are rejected as invalid
// kills even when the child exits non-zero.

import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const workerSrc = path.join(root, "workers", "scan-api", "src");
const dependencyDir = path.join(root, "workers", "scan-api", "node_modules");
const focusedRelative = "scripts/validate-as-c1-c2-c3-bounded-coverage.js";
const productionTargets = [
  "workers/scan-api/src/engines/asset-intel.js",
  "workers/scan-api/src/engines/attack-surface-lifecycle.js",
  "workers/scan-api/src/engines/attack-surface-signal-completeness.js",
  "workers/scan-api/src/engines/bounded-coverage.js",
  "workers/scan-api/src/engines/subdomains-scan.js",
];

const sha256 = (value) => crypto.createHash("sha256").update(value).digest("hex");
const fileSha = (file) => sha256(fs.readFileSync(file));
const snapshot = (files) => Object.fromEntries(files.map((file) => [file, fileSha(path.join(root, file))]));
const beforeTargets = snapshot(productionTargets);
const beforeWorktree = sha256(JSON.stringify(
  fs.readdirSync(root, { recursive: true, withFileTypes: true })
    .filter((entry) => entry.isFile() && !entry.parentPath.includes(`${path.sep}node_modules${path.sep}`))
    .map((entry) => path.relative(root, path.join(entry.parentPath, entry.name)).replaceAll(path.sep, "/"))
    .filter((file) => !file.startsWith(".git/"))
    .sort()
    .map((file) => [file, fileSha(path.join(root, file))]),
));

const collapsedDiscoveryCoverage = `const discoveryCoverage = {
    truncated: capReached,
    coverage_state: coverageStateFromTruncation(capReached),
  };`;

const registry = Object.freeze([
  {
    id: "M1",
    module: "asset",
    file: "workers/scan-api/src/engines/asset-intel.js",
    anchor: "const targets = candidates.slice(0, 50);",
    replacement: "const targets = candidates.slice(0, 300);",
    expected: [
      "F1_BOUNDED_EXPOSURE_NEVER_CLAIMS_COMPLETE_NO_SIGNAL",
      "F2_EXPOSURE_DENOMINATOR_AND_DROPPED_COUNT",
      "F7_RECHECK_SATURATION_IS_OBSERVABLE_ONLY",
      "F9_BOUNDED_COVERAGE_DOES_NOT_PROPAGATE_TO_SCAN_QUALITY",
      "P2_ALL_FOUR_CAPS_RETAINED",
      "P6_BOUNDED_SIGNAL_EXPOSES_ADDITIVE_CUSTOMER_COPY",
    ],
  },
  {
    id: "M2",
    module: "asset",
    file: "workers/scan-api/src/engines/asset-intel.js",
    anchor: "dropped_count: droppedCount,",
    replacement: "dropped_count: 0,",
    expected: ["F2_EXPOSURE_DENOMINATOR_AND_DROPPED_COUNT"],
  },
  {
    id: "M3",
    module: "coverage",
    file: "workers/scan-api/src/engines/bounded-coverage.js",
    anchor: 'return truncated === true ? "bounded" : "complete";',
    replacement: 'return "bounded";',
    expected: ["F10_UNBOUNDED_EXECUTION_IS_COMPLETE_NOT_ALWAYS_BOUNDED"],
  },
  {
    id: "M4",
    module: "lifecycle",
    file: "workers/scan-api/src/engines/attack-surface-lifecycle.js",
    anchor: ') === "bounded"\n        ? "not_assessed"\n        : null;',
    replacement: ') === "bounded"\n        ? null\n        : null;',
    expected: ["F6_BOUNDED_CT_SCOPE_FREEZES_LIFECYCLE"],
  },
  {
    id: "M5",
    module: "signal",
    file: "workers/scan-api/src/engines/attack-surface-signal-completeness.js",
    anchor: `if (coverageState === "bounded") {
    return exposureSignal("not_observed", "bounded_exposure_admin_probe_no_signal", {
      sources: ["http_probe", "asset_exposure_fingerprint"],
    });
  }`,
    replacement: `if (coverageState === "bounded") {
    return exposureSignal("not_observed", "complete_exposure_admin_probe_no_signal", {
      sources: ["http_probe", "asset_exposure_fingerprint"],
    });
  }`,
    expected: [
      "F1_BOUNDED_EXPOSURE_NEVER_CLAIMS_COMPLETE_NO_SIGNAL",
      "P6_BOUNDED_SIGNAL_EXPOSES_ADDITIVE_CUSTOMER_COPY",
    ],
  },
  {
    id: "M6",
    module: "asset",
    file: "workers/scan-api/src/engines/asset-intel.js",
    anchor: "candidate_total: candidateTotal,",
    replacement: "candidate_total: targets.length,",
    expected: [
      "F2_EXPOSURE_DENOMINATOR_AND_DROPPED_COUNT",
      "P6_BOUNDED_SIGNAL_EXPOSES_ADDITIVE_CUSTOMER_COPY",
    ],
  },
  {
    id: "M7",
    module: "coverage",
    file: "workers/scan-api/src/engines/bounded-coverage.js",
    anchor: 'return BOUNDED_COVERAGE_STATE_SET.has(value) ? value : "not_recorded";',
    replacement: 'return BOUNDED_COVERAGE_STATE_SET.has(value) ? value : "complete";',
    expected: ["F8_HISTORICAL_ABSENCE_PROJECTS_NOT_RECORDED"],
  },
  {
    id: "M8",
    module: "subdomains",
    file: "workers/scan-api/src/engines/subdomains-scan.js",
    anchor: `const discoveryCoverage = {
    crt_sh: {
      rows_received: crtRowsReceived,
      rows_examined: crtRowsExamined,
      rows_available: null,
      dropped_count: crtRowDroppedCount,
      row_cap_reached: crtRowCapReached,
    },
    per_provider: {
      crt_sh_unique_total: crtUniqueTotal,
      crt_sh_unique_kept: crtUniqueKept,
      crt_sh_dropped_count: crtUniqueDroppedCount,
      crt_sh_cap_reached: crtProviderCapReached,
      certspotter_unique_total: certSpotterUniqueTotal,
      certspotter_unique_kept: certSpotterUniqueKept,
      certspotter_dropped_count: certSpotterUniqueDroppedCount,
      certspotter_cap_reached: certSpotterProviderCapReached,
    },
    merged: {
      candidate_total: mergedCandidateTotal,
      kept: items.length,
      dropped_count: mergedDroppedCount,
      cap_reached: mergedCapReached,
      selection_order: "provider_response",
    },
    coverage_state: coverageStateFromTruncation(capReached),
  };`,
    replacement: collapsedDiscoveryCoverage,
    expected: [
      "F3_MERGED_CAP_DENOMINATOR_AND_DROPPED_COUNT",
      "F4_PER_PROVIDER_CAP_IS_INDEPENDENT",
      "F5_RAW_CRT_ROW_CAP_IS_INDEPENDENT",
      "P5_C2_MECHANISMS_REMAIN_SEPARATE",
      "P7_RAW_ROWS_AVAILABLE_DENOMINATOR_IS_NEVER_FABRICATED",
    ],
  },
  {
    id: "M9",
    module: "lifecycle",
    file: "workers/scan-api/src/engines/attack-surface-lifecycle.js",
    anchor: "asset_not_in_active_recheck_envelope",
    replacement: "mutant_removed_active_recheck_safeguard",
    occurrences: 2,
    expected: ["P4_KNOWN_ASSET_SAFEGUARD_REMAINS_EXACT"],
  },
]);

if (process.versions.node.split(".").map(Number)[0] !== 24) {
  throw new Error(`Node 24 required, got ${process.version}`);
}
if (!fs.existsSync(dependencyDir)) {
  throw new Error(`worker dependencies unavailable: ${dependencyDir}`);
}
if (registry.length !== 9 || registry.map(({ id }) => id).join(",") !== "M1,M2,M3,M4,M5,M6,M7,M8,M9") {
  throw new Error("semantic mutation registry must derive exactly M1..M9");
}

const record = process.env.AS_C123_RECORD_FAILURES === "1";
const invalidFailure = /(?:SyntaxError|TypeError|ReferenceError|ERR_MODULE_NOT_FOUND|ERR_PACKAGE_PATH_NOT_EXPORTED|fixture connection refused[^\n]*\nNode\.js)/;
const results = [];

for (const mutant of registry) {
  const sandbox = fs.mkdtempSync(path.join(os.tmpdir(), `as-c123-${mutant.id.toLowerCase()}-`));
  const sandboxResolved = fs.realpathSync(sandbox);
  try {
    fs.mkdirSync(path.join(sandbox, "scripts"), { recursive: true });
    fs.mkdirSync(path.join(sandbox, "workers", "scan-api"), { recursive: true });
    fs.cpSync(workerSrc, path.join(sandbox, "workers", "scan-api", "src"), { recursive: true });
    fs.cpSync(path.join(root, "shared"), path.join(sandbox, "shared"), { recursive: true });
    fs.copyFileSync(path.join(root, focusedRelative), path.join(sandbox, focusedRelative));
    fs.copyFileSync(
      path.join(root, "workers", "scan-api", "package.json"),
      path.join(sandbox, "package.json"),
    );
    fs.copyFileSync(
      path.join(root, "workers", "scan-api", "package.json"),
      path.join(sandbox, "workers", "scan-api", "package.json"),
    );
    fs.symlinkSync(dependencyDir, path.join(sandbox, "workers", "scan-api", "node_modules"), "dir");

    const target = path.join(sandbox, mutant.file);
    const source = fs.readFileSync(target, "utf8");
    const occurrences = source.split(mutant.anchor).length - 1;
    const expectedOccurrences = mutant.occurrences || 1;
    if (occurrences !== expectedOccurrences) {
      throw new Error(`${mutant.id} anchor count ${occurrences}, expected ${expectedOccurrences}`);
    }
    const mutated = source.split(mutant.anchor).join(mutant.replacement);
    if (mutated === source) throw new Error(`${mutant.id} replacement was a no-op`);
    fs.writeFileSync(target, mutated);
    const mutatedSha = fileSha(target);

    const child = spawnSync(process.execPath, [path.join(sandbox, focusedRelative)], {
      cwd: sandbox,
      encoding: "utf8",
      timeout: 120_000,
      env: { ...process.env, AS_C123_EMIT_MODULE_PROOF: "1" },
    });
    const output = `${child.stdout || ""}${child.stderr || ""}`;
    if (child.error) throw child.error;
    if (child.signal) throw new Error(`${mutant.id} child terminated by ${child.signal}`);
    if (child.status !== 1) throw new Error(`${mutant.id} expected exit 1, got ${child.status}\n${output}`);
    if (invalidFailure.test(output)) throw new Error(`${mutant.id} invalid non-semantic kill\n${output}`);
    const summary = output.match(/AS-C1\/C2\/C3 bounded coverage: (\d+)\/(\d+) passed, (\d+) failed/);
    const failures = output.match(/AS_C123_FAILURE_IDS (\[[^\n]+\])/);
    const proofMatch = output.match(/AS_C123_MODULE_PROOF (\{[^\n]+\})/);
    if (!summary || !failures || !proofMatch) {
      throw new Error(`${mutant.id} missing completed summary, failure IDs, or loaded-module proof\n${output}`);
    }
    const failureIds = JSON.parse(failures[1]);
    const proof = JSON.parse(proofMatch[1]);
    const loaded = proof[mutant.module];
    if (!loaded || !loaded.path.startsWith(`${sandboxResolved}${path.sep}`) || loaded.sha256 !== mutatedSha) {
      throw new Error(`${mutant.id} did not load the mutated target: ${JSON.stringify(loaded)}`);
    }
    if (Number(summary[3]) !== failureIds.length || failureIds.length === 0) {
      throw new Error(`${mutant.id} invalid semantic failure accounting: ${JSON.stringify(failureIds)}`);
    }
    if (!record && JSON.stringify(failureIds) !== JSON.stringify(mutant.expected)) {
      throw new Error(`${mutant.id} wrong-reason kill: got ${JSON.stringify(failureIds)}, expected ${JSON.stringify(mutant.expected)}`);
    }
    results.push({ id: mutant.id, failureIds, loaded_sha256: loaded.sha256 });
    console.log(`PASS ${mutant.id} ${JSON.stringify(failureIds)}`);
  } finally {
    const resolved = fs.realpathSync(sandbox);
    if (!resolved.startsWith(`${fs.realpathSync(os.tmpdir())}${path.sep}as-c123-`)) {
      throw new Error(`refusing unsafe sandbox cleanup: ${resolved}`);
    }
    fs.rmSync(resolved, { recursive: true });
  }
}

const afterTargets = snapshot(productionTargets);
if (JSON.stringify(afterTargets) !== JSON.stringify(beforeTargets)) {
  throw new Error("candidate production target bytes changed during mutation execution");
}
const afterWorktree = sha256(JSON.stringify(
  fs.readdirSync(root, { recursive: true, withFileTypes: true })
    .filter((entry) => entry.isFile() && !entry.parentPath.includes(`${path.sep}node_modules${path.sep}`))
    .map((entry) => path.relative(root, path.join(entry.parentPath, entry.name)).replaceAll(path.sep, "/"))
    .filter((file) => !file.startsWith(".git/"))
    .sort()
    .map((file) => [file, fileSha(path.join(root, file))]),
));
if (afterWorktree !== beforeWorktree) throw new Error("worktree bytes changed during mutation execution");

if (record) {
  console.log(`AS_C123_RECORDED_FAILURE_SETS ${JSON.stringify(results.map(({ id, failureIds }) => ({ id, failureIds })))}`);
} else {
  console.log(`AS-C1/C2/C3 semantic mutations: ${results.length}/${registry.length} caught for the exact expected reasons`);
  console.log("AS-C1/C2/C3 mutation validation passed; candidate target bytes and worktree restored");
}
