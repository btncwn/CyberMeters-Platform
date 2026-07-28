#!/usr/bin/env node
// Anchor-guarded mutation proof for the seven founder-required BRS regressions.
import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const businessRiskFile = path.join(root, "workers", "scan-api", "src", "engines", "business-risk.js");
const scanEngineFile = path.join(root, "workers", "scan-api", "src", "engines", "scan-engine.js");
const focusedValidator = path.join(root, "scripts", "validate-brs-partial-scan-honesty.js");
const engineValidator = path.join(root, "scripts", "validate-brs-partial-scan-engine-trace.js");
const EXPECTED_MUTANTS = 7;
const EXPECTED_ASSERTIONS = 7;

const replaceExactlyOnce = (source, anchor, replacement, label) => {
  const first = source.indexOf(anchor);
  if (first < 0 || source.indexOf(anchor, first + anchor.length) >= 0) {
    throw new Error(`${label}: anchor must exist exactly once`);
  }
  const mutated = source.slice(0, first) + replacement + source.slice(first + anchor.length);
  if (mutated === source) throw new Error(`${label}: mutated === original`);
  return mutated;
};

const mutants = [
  {
    name: "ignore scan quality",
    files: [businessRiskFile],
    mutate(files) {
      let source = files.get(businessRiskFile);
      source = replaceExactlyOnce(
        source,
        "if (!workspaceId || !scanId || quality !== SCAN_QUALITY.COMPLETE) {",
        "if (!workspaceId || !scanId) {",
        this.name,
      );
      source = replaceExactlyOnce(
        source,
        "AND s.status = 'completed' AND s.scan_quality = 'complete'",
        "AND s.status = 'completed'",
        this.name,
      );
      source = replaceExactlyOnce(
        source,
        "normalizeQuality(basisReport?.scan_quality?.status) !== SCAN_QUALITY.COMPLETE",
        "false",
        this.name,
      );
      files.set(businessRiskFile, source);
    },
    validator: focusedValidator,
    only: "partial does not overwrite canonical row",
    expected: "FAIL partial does not overwrite canonical row",
  },
  {
    name: "allow partial canonical overwrite",
    files: [businessRiskFile, scanEngineFile],
    mutate(files) {
      files.set(businessRiskFile, replaceExactlyOnce(
        files.get(businessRiskFile),
        "AND s.status = 'completed' AND s.scan_quality = 'complete'",
        "AND s.status = 'completed'",
        this.name,
      ));
      files.set(businessRiskFile, replaceExactlyOnce(
        files.get(businessRiskFile),
        "normalizeQuality(basisReport?.scan_quality?.status) !== SCAN_QUALITY.COMPLETE",
        "false",
        this.name,
      ));
      files.set(scanEngineFile, replaceExactlyOnce(
        files.get(scanEngineFile),
        `await computeAndPersistWorkspaceBrs(env, workspaceId, {
          scanId,
          scanQuality: scanQuality?.status,
          assessedAt: completedAt,
        });`,
        `await computeAndPersistWorkspaceBrs(env, workspaceId, {
          scanId,
          scanQuality: "complete",
          assessedAt: completedAt,
        });`,
        this.name,
      ));
    },
    validator: engineValidator,
    expected: "FAIL real partial scan preserves canonical BRS byte-for-byte",
  },
  {
    name: "append partial BRS trend history",
    files: [scanEngineFile],
    mutate(files) {
      files.set(scanEngineFile, replaceExactlyOnce(
        files.get(scanEngineFile),
        'if (scanQuality?.status === "complete") try {',
        "if (true) try {",
        this.name,
      ));
    },
    validator: engineValidator,
    expected: "FAIL real partial scan does not append a numeric BRS trend point",
  },
  {
    name: "expose stale stored number as current",
    files: [businessRiskFile],
    mutate(files) {
      files.set(businessRiskFile, replaceExactlyOnce(
        files.get(businessRiskFile),
        "if (basisIsCurrent && latestIsComplete) state = WORKSPACE_BRS_STATES.ASSESSED;",
        "if (lastComplete) state = WORKSPACE_BRS_STATES.ASSESSED;",
        this.name,
      ));
    },
    validator: focusedValidator,
    only: "latest partial current score unavailable",
    expected: "FAIL latest partial current score unavailable",
  },
  {
    name: "convert unavailable into A healthy",
    files: [businessRiskFile],
    mutate(files) {
      files.set(businessRiskFile, replaceExactlyOnce(
        files.get(businessRiskFile),
        `business_risk_score: null,
    score: null,
    brs: null,
    risk_band: null,
    band: null,
    grade: null,
    grade_label: null,`,
        `business_risk_score: 100,
    score: 100,
    brs: 100,
    risk_band: "low",
    band: "low",
    grade: "A",
    grade_label: "low",`,
        this.name,
      ));
    },
    validator: focusedValidator,
    only: "partial-only score unavailable never A",
    expected: "FAIL partial-only score unavailable never A",
  },
  {
    name: "conflate latest scan and BRS basis ids",
    files: [businessRiskFile],
    mutate(files) {
      files.set(businessRiskFile, replaceExactlyOnce(
        files.get(businessRiskFile),
        "lastComplete.stale = state !== WORKSPACE_BRS_STATES.ASSESSED;",
        `lastComplete.stale = state !== WORKSPACE_BRS_STATES.ASSESSED;
    if (currentAssessment) lastComplete.basis_scan.scan_id = currentAssessment.scan_id;`,
        this.name,
      ));
    },
    validator: focusedValidator,
    only: "latest and basis scan ids are not conflated",
    expected: "FAIL latest and basis scan ids are not conflated",
  },
  {
    name: "silently recompute older complete mixed-time basis",
    files: [businessRiskFile],
    mutate(files) {
      let source = files.get(businessRiskFile);
      source = replaceExactlyOnce(
        source,
        `WHERE s.id = ? AND s.workspace_id = ?
                  AND s.status = 'completed' AND s.scan_quality = 'complete'
                LIMIT 1\`)
      .bind(scanId, workspaceId).first(),`,
        `WHERE s.workspace_id = ?
                  AND s.status = 'completed' AND s.scan_quality = 'complete'
                ORDER BY s.created_at DESC LIMIT 1\`)
      .bind(workspaceId).first(),`,
        this.name,
      );
      files.set(businessRiskFile, source);
    },
    validator: focusedValidator,
    only: "missing exact current basis cannot silently choose older complete",
    expected: "FAIL missing exact current basis cannot silently choose older complete",
  },
];

let killed = 0;
let assertions = 0;
for (const mutant of mutants) {
  const originals = new Map(mutant.files.map((file) => [file, fs.readFileSync(file, "utf8")]));
  const mutated = new Map(originals);
  try {
    mutant.mutate(mutated);
    for (const file of mutant.files) {
      const before = originals.get(file);
      const after = mutated.get(file);
      if (after === before) throw new Error(`${mutant.name}: mutated === original for ${file}`);
      fs.writeFileSync(file, after);
    }
    const child = spawnSync(process.execPath, [mutant.validator], {
      cwd: root,
      encoding: "utf8",
      env: {
        ...process.env,
        ...(mutant.only ? { BRS_ASSERT_ONLY: mutant.only } : {}),
      },
      timeout: 60_000,
    });
    const output = `${child.stdout || ""}\n${child.stderr || ""}`;
    const nonzero = child.status !== 0;
    const intended = output.includes(mutant.expected);
    if (!nonzero || !intended) {
      console.error(`FAIL mutant ${mutant.name} escaped or failed for the wrong reason`);
      console.error(output.trim());
    } else {
      killed += 1;
      assertions += 1;
      console.log(`PASS mutant ${mutant.name} killed for intended reason`);
    }
  } finally {
    for (const [file, source] of originals) fs.writeFileSync(file, source);
  }
}

if (mutants.length !== EXPECTED_MUTANTS) {
  console.error(`FAIL pinned mutant count — got ${mutants.length} want ${EXPECTED_MUTANTS}`);
  process.exit(1);
}
if (killed !== EXPECTED_MUTANTS || assertions !== EXPECTED_ASSERTIONS) {
  console.error(
    `BRS mutations FAILED: mutants ${killed}/${EXPECTED_MUTANTS}, assertions ${assertions}/${EXPECTED_ASSERTIONS}`,
  );
  process.exit(1);
}
console.log(`BRS mutations passed: mutants ${killed}/${EXPECTED_MUTANTS}, assertions ${assertions}/${EXPECTED_ASSERTIONS}`);
