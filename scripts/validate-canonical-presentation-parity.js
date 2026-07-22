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
  const CANONICAL = new Set(["engines/scoring.js", "engines/assessment-presentation.js",
    // M5.e-C: the portfolio customer rating DELEGATES to the canonical band (that is the fix, not drift).
    "engines/portfolio-customers.js"]);
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
  // executive-workspace PDF (GET /api/workspaces/:id/report) headline delegates
  // to the canonical posture selector — NOT a raw AVG(score) that mixes partials.
  {
    // M5.d: the workspace report renders canonical snapshots — the inline
    // stats/trend queries and the local score-band brains are GONE, and the
    // route consumes readLatestWorkspaceSnapshots only.
    const pf = read("routes/portfolio.js");
    // Slice the workspace-report ROUTE BLOCK: portfolio analytics endpoints
    // legitimately aggregate; the report renderer must not.
    const wsReportBlock = pf.slice(pf.indexOf("workspace PDF report"), pf.indexOf("Portfolio Risk Engine"));
    ok("workspace report renders canonical snapshots (no inline stats queries)",
      /readLatestWorkspaceSnapshots/.test(wsReportBlock) && !/AVG\(/.test(wsReportBlock) && !/FROM findings|FROM scans/.test(wsReportBlock));
    const pdf = read("engines/pdf.js");
    ok("legacy buildPdfStreams brain is deleted (not merely unreferenced)",
      !/buildPdfStreams/.test(pdf) && !/scoreToRating/.test(pdf));
  }
  // workspace detail (GET /api/workspaces/:id) headline delegates to the canonical
  // selector — the raw average must never drive a rating on the detail page.
  {
    const wc = read("routes/workspaces-core.js");
    ok("workspace-detail delegates to the canonical current-posture helper",
      /getCurrentPosturePresentation/.test(wc));
    ok("workspace-detail cyber_score_average is complete-only",
      /ROUND\(AVG\(s\.score\), 1\)/.test(wc) && /s\.scan_quality = 'complete'/.test(wc));
    ok("workspace-detail response carries canonical posture fields",
      /posture_established:/.test(wc) && /posture_rating:/.test(wc));
    const wdp = fs.readFileSync(path.join(root, "frontend", "src", "pages", "WorkspaceDetailPage.jsx"), "utf8");
    ok("WorkspaceDetailPage renders posture, not an average-derived rating",
      /posture_established/.test(wdp) && !/avgRating/.test(wdp));
  }
  // workspace-insights current-findings aggregate delegates to the ONE canonical
  // latest-complete-scan scope (no bespoke MAX(created_at) tie-prone join).
  {
    const wi = read("routes/workspace-insights.js");
    ok("workspace-insights delegates to the canonical LATEST_COMPLETED_SCAN_SCOPE",
      /LATEST_COMPLETED_SCAN_SCOPE/.test(wi) && !/MAX\(created_at\) AS mx/.test(wi));
  }
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
  ok("posture-events uses Timeline Trust complete-only comparability gate",
    /loadTimelineComparisonContext/.test(read("engines/posture-events.js")) &&
    /currentQuality !== "complete"/.test(read("engines/timeline-trust.js")) &&
    /previousQuality !== "complete"/.test(read("engines/timeline-trust.js")) &&
    /currentVersion !== previousVersion/.test(read("engines/timeline-trust.js")));
}

// ── 4. Scan detail returns the canonical `assessment` decision ───────────────
{
  const sc = read("routes/scans.js");
  // M5.d: the assessment decision is FROZEN in the canonical snapshot; the
  // route serves it verbatim and never recomputes it on read.
  ok("scan-detail serves the snapshot's frozen assessment", /readScanReportSnapshot/.test(sc) && /const assessment = overall\.assessment/.test(sc));
  ok("scan-detail returns the canonical assessment object", /\n\s*assessment,/.test(sc));
  ok("scan-detail score_change is gated on comparability", /comparable && historicalChanges\?\.previous_score/.test(sc));
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
  // M5.d: both artifacts render the snapshot's frozen assessment; the snapshot
  // itself is composed through resolveAssessmentPresentation (the one brain).
  ok("executive report V2 renders the snapshot's frozen assessment", /overall\.assessment/.test(read("engines/executive-report.js")));
  ok("scan-report PDF renders the snapshot's frozen assessment fields", /assessment\?\.provisional/.test(read("engines/pdf.js")));
  // Score-drop alerts/emails only fire on a comparable (complete) delta.
  //
  // This counted TWO occurrences of the guard, because alerts.js held two
  // score-drop implementations: the live one in processAlertsForWorkspace and a
  // copy in shouldSendAlert — which was dead code (exported to nothing, called by
  // nothing) and was removed in the Alert Trust Foundation. Counting guards in dead
  // code proves nothing, so this now asserts the guard on the path that actually
  // fires: every LIVE score-drop trigger must gate on comparability.
  // Count TRIGGERS, not mentions: comments are stripped first. Without this, a
  // comment that merely quotes the threshold (PR-B4b's suppression rationale does)
  // reads as a second implementation and fails a correct codebase — the assertion is
  // about what the code DOES, so it must only look at code.
  const al = read("engines/alerts.js").replace(/\/\*[\s\S]*?\*\//g, "").replace(/\/\/[^\n]*/g, "");
  const liveScoreDrop = al.slice(al.indexOf("export async function processAlertsForWorkspace"));
  ok("the live score-drop trigger is gated on comparability",
     /score_change <= -10/.test(liveScoreDrop) && /comparable !== false/.test(liveScoreDrop));
  ok("no score-drop trigger exists outside the live processor",
     (al.match(/score_change <= -10/g) || []).length === 1);
}

// ── 6. Persistence: finalize + reconciler write scan_quality (D1↔R2 convergence) ─
{
  const se = read("engines/scan-engine.js");
  ok("finalizeScanResult persists scan_quality in the D1 UPDATE", /UPDATE scans SET status = \?, score = \?, rating = \?, scan_quality = \?/.test(se));
  ok("historical_scores INSERT carries scan_quality", /scan_quality[\s\S]{0,40}VALUES/.test(se) || /brs_score, scan_quality, created_at/.test(se));
  // PR-1 (22 Jul 2026): reconciliation moved to the canonical cron recovery
  // engine — GET routes are read-only display. The invariant is UNCHANGED and
  // now pinned at its canonical site: the converging UPDATE carries
  // scan_quality from the SAME R2 report.
  const scRecovery = read("engines/scan-recovery.js");
  ok("cron recovery converges scan_quality from R2 (canonical reconciler)",
    /UPDATE scans SET status = \?, score = \?, rating = \?, scan_quality = \?/.test(scRecovery) && /raw\.scan_quality\?\.status/.test(scRecovery));
  const scRoutes = read("routes/scans.js");
  ok("GET display correction presents scan_quality from R2 and stays read-only",
    /raw\.scan_quality\?\.status/.test(scRoutes) && !/UPDATE scans/.test(scRoutes));
}

console.log(`\ncanonical-presentation-parity: ${pass} passed, ${fail} failed`);
if (fail) { console.error("canonical-presentation-parity validation FAILED"); process.exit(1); }
console.log("canonical-presentation-parity validation passed");
