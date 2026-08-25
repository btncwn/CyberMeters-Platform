// Named mutation proof for the report-copy live-triage lane (D1-D4). Each mutant
// reintroduces exactly one defect in the product/registry source, re-runs the
// lane validator, and REQUIRES it to fail with the named assertion. The tree is
// fingerprinted and restored after every mutant (banked orphan-mutant guard).
import { execFileSync, spawnSync } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";

const root = path.resolve(new URL("../", import.meta.url).pathname);
const laneValidator = path.join(root, "scripts/validate-report-copy-live-triage.js");
const f = (rel) => path.join(root, rel);

function git(args) { return execFileSync("git", args, { cwd: root, encoding: "utf8" }); }
function worktreeFingerprint() {
  const status = git(["status", "--porcelain=v1", "-z"]);
  const paths = status.split("\0").filter(Boolean).map((e) => e.slice(3));
  const hash = crypto.createHash("sha256").update(status);
  for (const rel of paths.sort()) {
    const abs = path.join(root, rel);
    hash.update(rel); hash.update("\0");
    if (fs.existsSync(abs) && fs.statSync(abs).isFile()) hash.update(fs.readFileSync(abs));
    hash.update("\0");
  }
  return hash.digest("hex");
}
function replaceExactly(src, from, to, id) {
  const n = src.split(from).length - 1;
  if (n !== 1) throw new Error(`${id}: anchor count ${n}, expected 1`);
  return src.replace(from, to);
}
function runLane() {
  const child = spawnSync(process.execPath, [laneValidator], { cwd: root, encoding: "utf8", timeout: 120000 });
  return `${child.stdout || ""}\n${child.stderr || ""}`;
}

const mutants = [
  { id: "TRIAGE-M1-D1-pct-reintroduced", file: "workers/scan-api/src/engines/email-analysis.js",
    from: "    if (/^pct\\s*=/i.test(part)) continue;            // DMARCbis removed pct",
    to:   "    if (/^pct\\s*=/i.test(part)) { out.push(part); }  // DMARCbis removed pct",
    mustContain: "FAIL D1: upgrade drops the DMARCbis-removed pct tag" },
  { id: "TRIAGE-M2-D1-rua-overwritten", file: "workers/scan-api/src/engines/email-analysis.js",
    from: "    if (/^rua\\s*=/i.test(part)) { sawRua = true; }   // preserve existing rua verbatim",
    to:   "    if (/^rua\\s*=/i.test(part)) { continue; }        // preserve existing rua verbatim",
    mustContain: "FAIL D1: upgrade preserves the observed rua and does not overwrite it" },
  { id: "TRIAGE-M3-D1-spf-remove-plusall", file: "workers/scan-api/src/engines/remediation-registry.js",
    from: 'recommended_action: "Enumerate every authorised sending source, then replace the record\'s permissive ending (+all, ?all, or a ~all softfail you intend to harden) with -all once you are confident the inventory is complete.",',
    to:   'recommended_action: "Enumerate every authorised sending source, remove +all, and finish the record with -all once you are confident the inventory is complete.",',
    mustContain: "FAIL D1: SPF tighten action no longer says a bare 'remove +all'" },
  { id: "TRIAGE-M4-D2-axis-generic", file: "workers/scan-api/src/engines/dmarc-state.js",
    from: '    return "the aggregate-report (rua) destination authorisation could not be completed, so no policy or absence conclusion was made.";',
    to:   '    return null;',
    mustContain: "FAIL D2a: rua-authorisation gap names the rua axis" },
  { id: "TRIAGE-M5-D2-monitoring-divergence", file: "workers/scan-api/src/engines/dmarcbis-production.js",
    from: '    monitoring_state: complete ? "monitoring_healthy" : "monitoring_degraded",',
    to:   '    monitoring_state: policy.monitoring_state,',
    mustContain: "FAIL D2b: runDmarcbisCore recomputes monitoring_state from core completeness" },
  { id: "TRIAGE-M6-D3-suppression-disarmed", file: "workers/scan-api/src/engines/phase5-evidence.js",
    from: "  const skipped = [];\n  for (const key of SCORE_BEARING_MODULES) {",
    to:   "  const skipped = [];\n  if (skipped) return skipped;\n  for (const key of SCORE_BEARING_MODULES) {",
    mustContain: "FAIL D3 isolation: complete evidence + skipped score-bearing module STILL nulls the score" },
  { id: "TRIAGE-M7-D3-methodology-not-bumped", file: "workers/scan-api/src/engines/scoring.js",
    from: 'export const CYBER_METRICS_SCORE_METHODOLOGY_VERSION = "2026-08-24.1";',
    to:   'export const CYBER_METRICS_SCORE_METHODOLOGY_VERSION = "2026-08-23.1";',
    mustContain: "FAIL D3: methodology stamp bumped to 2026-08-24.1" },
  { id: "TRIAGE-M8-D4-hosted-shortcircuit-removed", file: "workers/scan-api/src/engines/dmarcbis-resolver.js",
    from: "  return host === hosted || host.endsWith(`.${hosted}`);",
    to:   "  return false;",
    mustContain: "FAIL D4: hosted destination resolves not_required_cybermeters_hosted" },
  { id: "TRIAGE-M9-D3-historical-stale-score-revived", file: "workers/scan-api/src/engines/phase5-evidence.js",
    from: "  if (customer.suppressed !== true) {",
    to:   "  if (customer.evidence.complete) {",
    mustContain: "FAIL D3 historical: complete phase5 plus skip cannot retain a stale numeric score" },
  { id: "TRIAGE-M10-D3-snapshot-stale-conclusions-revived", file: "workers/scan-api/src/engines/phase5-evidence.js",
    from: "  if (projection.suppressed !== true) return websiteSnapshot;",
    to:   "  if (projection.evidence.complete) return websiteSnapshot;",
    mustContain: "FAIL D3 snapshot: suppression nulls score, band, summary and BRI together" },
  { id: "TRIAGE-M11-D3-current-posture-revived", file: "workers/scan-api/src/engines/current-posture.js",
    from: "    const value = phase5.assessment;",
    to:   "    const value = phase5.evidence.complete\n      ? { ...phase5.assessment, raw_score: row.score, display_score: row.score, display_rating: row.rating, authoritative: true, provisional: false }\n      : phase5.assessment;",
    mustContain: "FAIL D3 current posture: a suppressed complete row cannot become authoritative" },
  { id: "TRIAGE-M12-D3-composed-BRI-revived", file: "workers/scan-api/src/engines/report-snapshot.js",
    from: "  const phase5Suppressed = phase5Projection.suppressed === true;",
    to:   "  const phase5Suppressed = false;",
    mustContain: "FAIL D3 composition: Phase5 decision nulls every stale report conclusion" },
  { id: "TRIAGE-M13-D3-ScanDetail-cause-removed", file: "frontend/src/pages/ScanDetail.jsx",
    from: "                  {assessmentScore === null && assessmentReason && (",
    to:   "                  {false && assessmentReason && (",
    mustContain: "FAIL D3 ScanDetail wire-in: null score renders the backend assessment reason" },
  { id: "TRIAGE-M14-D3-complete-no-score-authorized", file: "workers/scan-api/src/engines/assessment-presentation.js",
    from: "    authoritative:  complete && hasScore,\n    comparable:     complete && hasScore,",
    to:   "    authoritative:  complete,\n    comparable:     complete,",
    mustContain: "FAIL D3 no-score invariant: complete quality alone is never authoritative or comparable" },
];

let killed = 0; const failures = [];
const initial = worktreeFingerprint();
for (const m of mutants) {
  const abs = f(m.file);
  const original = fs.readFileSync(abs);
  try {
    const mutated = replaceExactly(original.toString("utf8"), m.from, m.to, m.id);
    if (mutated === original.toString("utf8")) throw new Error("mutation changed no bytes");
    fs.writeFileSync(abs, mutated);
    const out = runLane();
    if (out.includes(m.mustContain)) { killed += 1; console.log(`PASS ${m.id} killed by: ${m.mustContain}`); }
    else { failures.push(m.id); console.error(`FAIL ${m.id} — lane did not fail with "${m.mustContain}"`); }
  } catch (e) {
    failures.push(m.id); console.error(`FAIL ${m.id} — ${e?.message || e}`);
  } finally {
    fs.writeFileSync(abs, original);
    if (worktreeFingerprint() !== initial) { failures.push(`${m.id}-restore`); console.error(`FAIL ${m.id} worktree not restored`); }
  }
}

console.log(`\nreport-copy live triage mutations: ${killed}/${mutants.length} killed`);
if (failures.length) { console.error(`mutations FAILED: ${failures.join(", ")}`); process.exit(1); }
