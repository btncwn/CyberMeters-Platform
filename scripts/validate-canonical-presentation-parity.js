#!/usr/bin/env node
//
// Canonical-presentation PARITY contract. Static guard proving the whole product
// renders ONE completeness-aware decision. It FAILS if a production consumer:
//   • calls riskLevelForScore() directly for display (divergent rating derivation),
//   • presents an authoritative score/rating without delegating to the canonical
//     current-posture selector,
//   • computes a score-trend delta from scans/historical_scores that are not
//     restricted to complete quality,
//   • or returns a scan's score/rating without the canonical `assessment` decision.
// This is the regression that fails when a new surface re-introduces a clean rating
// for a partial/degraded scan. Node 24+. CI-blocking.
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const S = path.join(root, "workers", "scan-api", "src");
const read = (rel) => fs.readFileSync(path.join(S, rel), "utf8");
let pass = 0, fail = 0;
const ok = (n, c, d = "") => { c ? pass++ : fail++; if (!c) console.log(`FAIL ${n}${d ? " — " + d : ""}`); };

// Walk every .js under the worker src.
function walk(dir) {
  const out = [];
  for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
    const p = path.join(dir, e.name);
    if (e.isDirectory()) out.push(...walk(p));
    else if (e.name.endsWith(".js")) out.push(p);
  }
  return out;
}
const files = walk(S);

// ── 1. riskLevelForScore() is called ONLY inside the canonical seam ──────────
// The score→label helper stays pure; ANY other call site is a divergent rating.
{
  const CANONICAL = new Set(["engines/scoring.js", "engines/assessment-presentation.js"]);
  const offenders = [];
  for (const f of files) {
    const rel = path.relative(S, f);
    if (CANONICAL.has(rel)) continue;
    const src = fs.readFileSync(f, "utf8");
    // Match an actual invocation `riskLevelForScore(` (not an import/re-export list).
    for (const line of src.split("\n")) {
      if (/riskLevelForScore\s*\(/.test(line) && !/import|export|\/\//.test(line)) offenders.push(`${rel}: ${line.trim().slice(0, 70)}`);
    }
  }
  ok(`riskLevelForScore() has no divergent display call site (${offenders.length} found)`, offenders.length === 0, offenders.join(" | "));
}

// ── 2. Authoritative current-posture consumers delegate to the canonical selector ─
{
  const consumers = ["engines/scorecard.js", "routes/executive-dashboard.js"];
  for (const c of consumers) {
    const src = read(c);
    ok(`${c} delegates to the canonical current-posture helper`,
      /getCurrentPosturePresentation|getAuthoritativeCurrentPosture/.test(src));
    ok(`${c} no longer emits a raw latestScan score/rating as the headline`,
      !/security_score:\s*latestScan\?\.score|risk_(level|rating):\s*latestScan\?\.rating/.test(src));
  }
  // workspace-insights authoritative aggregate is complete-only.
  ok("workspace-insights latest-posture aggregate is complete-only",
    (read("routes/workspace-insights.js").match(/status = 'completed' AND scan_quality = 'complete'/g) || []).length >= 2);
  // portfolio per-customer rating uses latest COMPLETE scan.
  ok("portfolio per-customer rating uses latest COMPLETE scan",
    /scan_quality='complete'/.test(read("engines/portfolio-customers.js")));
}

// ── 3. Score-trend deltas are restricted to complete assessments ─────────────
{
  const ed = read("routes/executive-dashboard.js");
  // The last-2 historical_scores delta query must filter complete quality.
  ok("exec-dashboard score-delta query is complete-only",
    /historical_scores WHERE workspace_id = \? AND scan_quality = 'complete'[\s\S]{0,60}LIMIT 2/.test(ed));
  // Trend baselines (per-scan comparisons) require a complete baseline.
  ok("historical-scan trend baseline is complete-only",
    /scan_quality = 'complete'/.test(read("engines/historical-scan.js")));
  ok("posture-events baseline is complete-only",
    /scan_quality = 'complete'/.test(read("engines/posture-events.js")));
}

// ── 4. Scan detail returns the canonical `assessment` decision ───────────────
{
  const sc = read("routes/scans.js");
  ok("scan-detail delegates to resolveAssessmentPresentation", /resolveAssessmentPresentation/.test(sc));
  ok("scan-detail returns the canonical assessment object", /\n\s*assessment,/.test(sc));
  ok("scan-detail score_change is gated on comparability", /assessment\.comparable && historicalChanges\?\.previous_score/.test(sc));
  // The scan LIST + history API must carry scan_quality so no client can reconstruct
  // a clean rating from a partial scan.
  ok("scan-list API selects scan_quality", /s\.rating, s\.scan_quality, s\.created_at/.test(sc));
  ok("scan-history API selects scan_quality", /s\.score, s\.rating, s\.scan_quality, s\.created_at/.test(sc));
}

// ── 4b. Main Dashboard hero is completeness-aware (authoritative = latest complete) ─
{
  const dash = fs.readFileSync(path.join(root, "frontend", "src", "pages", "Dashboard.jsx"), "utf8");
  ok("Dashboard authoritative posture = latest complete-quality scan", /scan_quality === 'complete'/.test(dash));
  ok("Dashboard suppresses the rating for a provisional latest", /postureProvisional \? null : ins\.riskLevel/.test(dash));
}

// ── 5. Report + PDF delegate to the resolver (customer artifacts) ────────────
{
  ok("executive report V2 delegates to resolveAssessmentPresentation", /resolveAssessmentPresentation/.test(read("engines/executive-report.js")));
  ok("scan-report PDF delegates to resolveAssessmentPresentation", /resolveAssessmentPresentation/.test(read("engines/pdf.js")));
}

// ── 6. Persistence: finalize + reconciler write scan_quality (D1↔R2 convergence) ─
{
  const se = read("engines/scan-engine.js");
  ok("finalizeScanResult persists scan_quality in the D1 UPDATE", /UPDATE scans SET status = \?, score = \?, rating = \?, scan_quality = \?/.test(se));
  ok("historical_scores INSERT carries scan_quality", /scan_quality[\s\S]{0,40}VALUES/.test(se) || /brs_score, scan_quality, created_at/.test(se));
  const scReconciler = read("routes/scans.js");
  ok("stuck-scan reconciler converges scan_quality from R2",
    /UPDATE scans SET status = \?, score = \?, rating = \?, scan_quality = \?/.test(scReconciler) && /raw\.scan_quality\?\.status/.test(scReconciler));
}

console.log(`\ncanonical-presentation-parity: ${pass} passed, ${fail} failed`);
if (fail) { console.error("canonical-presentation-parity validation FAILED"); process.exit(1); }
console.log("canonical-presentation-parity validation passed");
