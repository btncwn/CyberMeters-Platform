#!/usr/bin/env node
// Pre-Item11 Blocker 3 — strict fresh-process mutation proof for the
// workspace Related-Changes scope + ASM takeover traceability corrective.
//
// Every mutant changes REAL production source, runs the focused fixture
// validator (validate-report-scope-traceability.js) in a fresh process, and is
// accepted only when it exits exactly 1 for its exact pinned FAIL-name set.
// Two invalid-kill controls prove the harness itself rejects no-op edits and
// load/syntax deaths as kills. Source bytes and the complete intended
// working-tree diff are restored and SHA-256 checked after the suite.
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const validator = path.join(root, "scripts", "validate-report-scope-traceability.js");
const derive = process.argv.includes("--derive");

const EXPECTED_MUTANTS = 13;
const EXPECTED_CONTROLS = 2;
const VALIDATOR_ASSERTIONS = 36;
const SUMMARY_PREFIX = "Report scope & takeover traceability:";

const T = Object.freeze({
  pdf: "workers/scan-api/src/engines/pdf.js",
  rc: "workers/scan-api/src/engines/related-changes.js",
  pres: "workers/scan-api/src/engines/attack-surface-customer-presentation.js",
  asm: "workers/scan-api/src/engines/asm-cases.js",
  ucRoute: "workers/scan-api/src/routes/managed-cases.js",
  detailPage: "frontend/src/pages/ws/WorkspaceCaseDetailPage.jsx",
});

// Fixture-validator assertion names (must match validate-report-scope-traceability.js).
const A1C = "A1c summary item names the canonical affected domain";
const A1D = "A1d PDF section heading is workspace-level";
const A1E = "A1e PDF row names the affected domain";
const A1F = "A1f PDF never attributes a cross-domain change to the report subject";
const A2A = "A2a same-domain row stays workspace-labeled with its affected domain";
const A3A = "A3a multi-domain summary is deterministic and retains each affected domain";
const A4A = "A4a different-workspace change is excluded from the summary";
const A4B = "A4b different-workspace change is excluded from the PDF";
const B1A = "B1a takeover observed presentation is informational, never confirmed";
const B1B = "B1b frozen takeover observed message is re-projected to the canonical wording";
const B6A = "B6a case with a qualifying current finding is linked to current evidence";
const B7A = "B7a open case without a current finding is retained historical";
const B7B = "B7b historical case is never attributed to the current scan";
const B7C = "B7c reopened case without a current finding reads as recurrence/monitoring";
const B9A = "B9a not-observed wording never claims absence or removal";
const B10A = "B10a legacy case provenance is explicit unknown, never attributed to a scan";
const B11A = "B11a universal and ASM case surfaces attach identical traceability";
const B11B = "B11b case detail surfaces the same traceability classification";
const B11C = "B11c PDF renders the canonical takeover wording via the shared projection";
const B12A = "B12a foreign-workspace cases are invisible through the case surface";
const B12D = "B12d traceability projection never mutates case rows or history";
const B13B = "B13b frontend never derives the relationship from raw enum values";

const mutants = [
  {
    name: "PDF drops the workspace-level section label",
    target: T.pdf,
    anchor: "w.heading(`Workspace-level Related Changes observed in this period (${items.length})`);",
    replacement: "w.heading(`Related Changes observed in this period (${items.length})`);",
    expectedFailures: [A1D, A2A],
  },
  {
    name: "PDF replaces the affected domain with the report subject",
    target: T.pdf,
    anchor: "    w.text(`${label} - affects ${affected}`, { size: 10, bold: true });",
    replacement: "    w.text(`${label} - affects ${subject || affected}`, { size: 10, bold: true });",
    expectedFailures: [A1F],
  },
  {
    name: "summary admits a different-workspace change",
    target: T.rc,
    anchor: `         FROM related_changes
        WHERE workspace_id = ?
        ORDER BY last_seen DESC, id ASC`,
    replacement: `         FROM related_changes
        WHERE (workspace_id = ? OR 1=1)
        ORDER BY last_seen DESC, id ASC`,
    expectedFailures: [A4A, A4B],
  },
  {
    name: "summary drops the affected-domain identity",
    target: T.rc,
    anchor: "    affected_domain: r.registrable_domain,",
    replacement: "    affected_domain: null,",
    expectedFailures: [A1C, A2A, A3A],
  },
  {
    name: "classifier promotes a passive observation to a current-finding link",
    target: T.pres,
    anchor: "  const hasMatchingFinding = currentAssessed && findingId != null && ids.has(String(findingId));",
    replacement: "  const hasMatchingFinding = currentAssessed;",
    expectedFailures: [B7A, B7B, B7C, B10A, B11A, B11B],
  },
  {
    name: "takeover observed wording claims a confirmed takeover",
    target: T.pres,
    anchor: '    return "Takeover candidate evidence was observed in the recorded scope. This is an informational observation: it is not a confirmed takeover, not a verified exploitable vulnerability, and not a current customer finding unless one is separately recorded. Detection alone does not establish maliciousness or compromise.";',
    replacement: '    return "Takeover candidate evidence was observed in the recorded scope. A confirmed takeover was identified for this host.";',
    expectedFailures: [B1A, B1B, B11C],
  },
  {
    name: "classifier attributes an unknown origin to the current scan",
    target: T.pres,
    anchor: `  const originScanId = caseRow?.source_scan_id
    || (typeof evidence?.scan_id === "string" && evidence.scan_id ? evidence.scan_id : null)
    || null;`,
    replacement: `  const originScanId = caseRow?.source_scan_id
    || (typeof evidence?.scan_id === "string" && evidence.scan_id ? evidence.scan_id : null)
    || (currentScan && currentScan.scan_id)
    || null;`,
    expectedFailures: [B10A],
  },
  {
    name: "lifecycle not-observed wording claims removal",
    target: T.pres,
    anchor: '    case "not_observed":\n      return "The asset was not observed in this scan. This is not confirmed removal.";',
    replacement: '    case "not_observed":\n      return "The asset was not observed in this scan and has been removed.";',
    expectedFailures: [B9A],
  },
  {
    name: "traceability derivation auto-closes retained cases",
    target: T.asm,
    anchor: `  for (const c of asmRows) {
    const context = contexts.get(normaliseDomain(c.domain))
      || { currentScan: null, currentFindingIds: null };
    out.set(c.id ?? c.case_id, classifyAsmCaseTraceability(c, context));
  }`,
    replacement: `  for (const c of asmRows) {
    const context = contexts.get(normaliseDomain(c.domain))
      || { currentScan: null, currentFindingIds: null };
    const t = classifyAsmCaseTraceability(c, context);
    if (t.relationship === "retained_historical") {
      try {
        await env.cybermeters_db
          .prepare("UPDATE managed_cases SET status = 'closed', updated_at = datetime('now') WHERE id = ? AND workspace_id = ?")
          .bind(c.id ?? c.case_id, workspaceId)
          .run();
      } catch { /* mutant */ }
    }
    out.set(c.id ?? c.case_id, t);
  }`,
    expectedFailures: [B12D],
  },
  {
    name: "traceability derivation rewrites historical case evidence",
    target: T.asm,
    anchor: "    out.set(c.id ?? c.case_id, classifyAsmCaseTraceability(c, context));",
    replacement: `    try {
      await env.cybermeters_db
        .prepare("UPDATE managed_cases SET evidence_json = ? WHERE id = ? AND workspace_id = ?")
        .bind(JSON.stringify({ scan_id: context.currentScan ? context.currentScan.scan_id : null }), c.id ?? c.case_id, workspaceId)
        .run();
    } catch { /* mutant */ }
    out.set(c.id ?? c.case_id, classifyAsmCaseTraceability(c, context));`,
    expectedFailures: [B12D],
  },
  {
    name: "PDF bypasses the canonical presentation re-projection",
    target: T.pdf,
    anchor: "  const assurance = attackSurfaceAssuranceFromSnapshot(snap);",
    replacement: "  const assurance = snap.attack_surface_assurance || attackSurfaceAssuranceFromSnapshot(snap);",
    expectedFailures: [B11C],
  },
  {
    name: "frontend derives its own relationship label from the raw enum",
    target: T.detailPage,
    anchor: '<dd className="text-slate-700 mt-0.5 font-medium">{c.traceability.relationship_label}</dd>',
    replacement: "<dd className=\"text-slate-700 mt-0.5 font-medium\">{c.traceability.relationship === 'retained_historical' ? 'Resolved historically' : c.traceability.relationship_label}</dd>",
    expectedFailures: [B13B],
  },
  {
    name: "universal case list drops the workspace guard",
    target: T.ucRoute,
    anchor: '      const where = ["workspace_id = ?"];\n      const binds = [wsId];',
    replacement: '      const where = ["(workspace_id = ? OR 1=1)"];\n      const binds = [wsId];',
    expectedFailures: [B12A],
  },
];

// Invalid-kill controls: the harness must NOT count these as kills.
const controls = [
  {
    name: "control: comment-only no-op must not kill anything",
    target: T.pres,
    anchor: "// ── ASM case traceability (pre-Item11 blocker 3) ─────────────────────────────",
    replacement: "// ── ASM case traceability (pre-Item11 blocker 3) — control no-op edit ────────",
    expect: "green",
  },
  {
    name: "control: syntax-breaking edit must be classified as invalid, not a kill",
    target: T.pres,
    anchor: "export function classifyAsmCaseTraceability(caseRow, { currentScan = null, currentFindingIds = null } = {}) {",
    replacement: "export function classifyAsmCaseTraceability(caseRow, { currentScan = null, currentFindingIds = null } = {} {",
    expect: "invalid",
  },
];

const sha256 = (value) => crypto.createHash("sha256").update(value).digest("hex");
const runGit = (args, encoding = "utf8") => {
  const result = spawnSync("git", args, { cwd: root, encoding });
  if (result.error || result.signal !== null || result.status !== 0) {
    throw new Error(`git ${args.join(" ")} failed: ${result.error?.message || result.stderr || result.signal || result.status}`);
  }
  return result.stdout;
};
const workingTreeFingerprint = () => {
  const status = runGit(["status", "--porcelain=v1", "--untracked-files=all"]);
  const diff = runGit(["diff", "--binary", "--no-ext-diff", "HEAD", "--", "."]);
  const untrackedRaw = runGit(["ls-files", "--others", "--exclude-standard", "-z"], "buffer");
  const untracked = untrackedRaw.toString("utf8").split("\0").filter(Boolean).sort()
    .filter((rel) => fs.statSync(path.join(root, rel)).isFile()).map((rel) => {
      const bytes = fs.readFileSync(path.join(root, rel));
      return `${rel}\0${sha256(bytes)}`;
    }).join("\n");
  return { status, diff, untracked, hash: sha256(`${status}\0${diff}\0${untracked}`) };
};
const replaceExactlyOnce = (source, anchor, replacement, label) => {
  const first = source.indexOf(anchor);
  if (first < 0 || source.indexOf(anchor, first + anchor.length) >= 0) {
    throw new Error(`${label}: anchor must exist exactly once`);
  }
  const mutated = source.slice(0, first) + replacement + source.slice(first + anchor.length);
  if (mutated === source) throw new Error(`${label}: mutated === original`);
  return mutated;
};
const runValidator = () => spawnSync(process.execPath, [validator], {
  cwd: root,
  encoding: "utf8",
  timeout: 300_000,
});
const failNames = (output) => output
  .split("\n")
  .filter((line) => line.startsWith("FAIL "))
  .map((line) => line.slice(5).split(" — ")[0].trim())
  .sort();
const summaryTotals = (output) => {
  const line = output.split("\n").find((candidate) => candidate.startsWith(SUMMARY_PREFIX));
  if (!line) return null;
  const match = line.match(/(\d+) passed, (\d+) failed \((\d+) total\)/);
  if (!match) return null;
  return { pass: Number(match[1]), fail: Number(match[2]), total: Number(match[3]), line };
};
const loadDeath = (output) =>
  /SyntaxError|ERR_MODULE_NOT_FOUND|Cannot find module|Failed to load url|Transform failed/.test(output);

const originals = new Map();
for (const rel of Object.values(T)) originals.set(rel, fs.readFileSync(path.join(root, rel)));
const beforeShas = new Map([...originals].map(([rel, buf]) => [rel, sha256(buf)]));
const beforeTree = workingTreeFingerprint();

let killed = 0;
let controlsPassed = 0;
let suiteFailures = 0;
const restore = (rel) => fs.writeFileSync(path.join(root, rel), originals.get(rel));

try {
  if (mutants.length !== EXPECTED_MUTANTS) {
    throw new Error(`pinned mutant count drift: got ${mutants.length}, want ${EXPECTED_MUTANTS}`);
  }
  if (controls.length !== EXPECTED_CONTROLS) {
    throw new Error(`pinned control count drift: got ${controls.length}, want ${EXPECTED_CONTROLS}`);
  }

  const baseline = runValidator();
  const baselineOutput = `${baseline.stdout || ""}\n${baseline.stderr || ""}`;
  const baselineTotals = summaryTotals(baselineOutput);
  if (
    baseline.error || baseline.signal !== null || baseline.status !== 0 ||
    !baselineTotals || baselineTotals.pass !== VALIDATOR_ASSERTIONS ||
    baselineTotals.fail !== 0 || baselineTotals.total !== VALIDATOR_ASSERTIONS
  ) {
    throw new Error(`baseline validator is not ${VALIDATOR_ASSERTIONS}/${VALIDATOR_ASSERTIONS} green\n${baselineOutput.trim()}`);
  }
  console.log(`PASS baseline validator green (${VALIDATOR_ASSERTIONS}/${VALIDATOR_ASSERTIONS})`);

  for (const mutant of mutants) {
    const rel = mutant.target;
    const mutated = replaceExactlyOnce(originals.get(rel).toString("utf8"), mutant.anchor, mutant.replacement, mutant.name);
    fs.writeFileSync(path.join(root, rel), mutated);
    try {
      const child = runValidator();
      const output = `${child.stdout || ""}\n${child.stderr || ""}`;
      const totals = summaryTotals(output);
      const got = failNames(output);
      if (derive) {
        console.log(`DERIVE ${mutant.name}\n  status=${child.status} fails=${JSON.stringify(got)}`);
        continue;
      }
      const want = [...mutant.expectedFailures].sort();
      const problems = [];
      if (child.error) problems.push(`spawn error: ${child.error.message}`);
      if (child.signal !== null) problems.push(`signal: ${child.signal}`);
      if (child.status !== 1) problems.push(`exit status ${child.status}, want exactly 1`);
      if (loadDeath(output)) problems.push("child failed to parse/import/load; not a behavioural kill");
      if (!totals) {
        problems.push("validator summary missing");
      } else {
        if (totals.total !== VALIDATOR_ASSERTIONS) problems.push(`assertion total ${totals.total}, want ${VALIDATOR_ASSERTIONS}`);
        if (totals.fail !== want.length || totals.pass !== VALIDATOR_ASSERTIONS - want.length) {
          problems.push(`summary ${totals.pass} pass/${totals.fail} fail does not match pinned FAIL count ${want.length}`);
        }
      }
      if (JSON.stringify(got) !== JSON.stringify(want)) {
        problems.push(`FAIL set mismatch — got [${got.join(" | ")}] want [${want.join(" | ")}]`);
      }
      if (problems.length) {
        suiteFailures += 1;
        console.error(`FAIL mutant "${mutant.name}" escaped or died for the wrong reason`);
        for (const problem of problems) console.error(`  - ${problem}`);
        console.error(output.trim().slice(0, 4000));
      } else {
        killed += 1;
        console.log(`PASS mutant "${mutant.name}" killed by exactly: ${want.join(" | ")}`);
      }
    } finally {
      restore(rel);
    }
  }

  for (const control of controls) {
    const rel = control.target;
    const mutated = replaceExactlyOnce(originals.get(rel).toString("utf8"), control.anchor, control.replacement, control.name);
    fs.writeFileSync(path.join(root, rel), mutated);
    try {
      const child = runValidator();
      const output = `${child.stdout || ""}\n${child.stderr || ""}`;
      const totals = summaryTotals(output);
      if (control.expect === "green") {
        const green = !child.error && child.signal === null && child.status === 0 &&
          totals && totals.pass === VALIDATOR_ASSERTIONS && totals.fail === 0;
        if (green) { controlsPassed += 1; console.log(`PASS ${control.name}`); }
        else {
          suiteFailures += 1;
          console.error(`FAIL ${control.name} — a no-op edit changed validator behaviour`);
          console.error(output.trim().slice(0, 2000));
        }
      } else {
        // A load/syntax death must be DETECTED as invalid: the child must not
        // report a clean pinned-FAIL run, and the harness's own classifier must
        // flag it. This proves a dead module can never be scored as a kill.
        const detectedInvalid = loadDeath(output) || !totals;
        const cleanBehaviouralFail = child.status === 1 && totals && !loadDeath(output);
        if (detectedInvalid && !cleanBehaviouralFail) { controlsPassed += 1; console.log(`PASS ${control.name}`); }
        else {
          suiteFailures += 1;
          console.error(`FAIL ${control.name} — a load death was not classified as invalid`);
          console.error(output.trim().slice(0, 2000));
        }
      }
    } finally {
      restore(rel);
    }
  }
} catch (error) {
  suiteFailures += 1;
  console.error(`FAIL mutation suite setup/baseline — ${error.message}`);
} finally {
  for (const rel of Object.values(T)) restore(rel);
}

let restoreFailures = 0;
for (const [rel, before] of beforeShas) {
  const after = fs.readFileSync(path.join(root, rel));
  if (sha256(after) !== before || !after.equals(originals.get(rel))) {
    restoreFailures += 1;
    console.error(`FAIL production source SHA-256 changed for ${rel}`);
  }
}
if (restoreFailures === 0) console.log("PASS every mutated production source restored byte-exactly");
let afterTree = null;
try {
  afterTree = workingTreeFingerprint();
} catch (error) {
  suiteFailures += 1;
  console.error(`FAIL post-suite working-tree fingerprint — ${error.message}`);
}
if (!afterTree || afterTree.hash !== beforeTree.hash || afterTree.status !== beforeTree.status ||
    afterTree.diff !== beforeTree.diff || afterTree.untracked !== beforeTree.untracked) {
  suiteFailures += 1;
  console.error(`FAIL working-tree diff changed: before=${beforeTree.hash} after=${afterTree?.hash || "unavailable"}`);
} else {
  console.log(`PASS working-tree diff restored exactly (${afterTree.hash})`);
}

if (derive) {
  console.log("derive mode complete (no verdict)");
  process.exit(0);
}
if (killed !== EXPECTED_MUTANTS || controlsPassed !== EXPECTED_CONTROLS || suiteFailures > 0 || restoreFailures > 0) {
  console.error(`Report scope & traceability mutations FAILED: ${killed}/${EXPECTED_MUTANTS} exact kills; controls ${controlsPassed}/${EXPECTED_CONTROLS}; suite failures=${suiteFailures + restoreFailures}`);
  process.exit(1);
}
console.log(`Report scope & traceability mutations passed: ${killed}/${EXPECTED_MUTANTS} killed with exact FAIL sets; ${controlsPassed}/${EXPECTED_CONTROLS} invalid-kill controls held; no signal/load/syntax/wrong-reason kill`);
