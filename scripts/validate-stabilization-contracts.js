#!/usr/bin/env node
//
// Security-invariant-stabilization contracts. Static guards that FAIL CI if any of
// the route-level fixes in this release regress:
//   • 403/404 existence-oracle collapse (Episode 4)
//   • scheduled-catch downgrade guard + detail-reconciler scan_quality (Episode 5)
//   • DMARC-ingest fail-closed rate limit (Episode 6)
//   • dead sendScoreDropAlert removed (Episode 7)
//   • current-findings canonical scope shared by dashboard/insights/report/PDF (Episode 3)
// These complement the behavioural tests (scheduled-eligibility, email-entitlement,
// current-findings-dedup). Node 24+. CI-blocking.
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const S = path.join(root, "workers", "scan-api", "src");
const read = (rel) => fs.readFileSync(path.join(S, rel), "utf8");
let pass = 0, fail = 0;
const ok = (n, c, d = "") => { c ? pass++ : fail++; if (!c) console.log(`FAIL ${n}${d ? " — " + d : ""}`); };

// ── Episode 4 — existence oracle collapsed to identical 403 ──────────────────
{
  const sc = read("routes/scans.js");
  // report + detail handlers: a missing scan now returns 403 (identical to a foreign
  // scan) instead of a 404 that leaks non-existence.
  ok("scan report/detail handlers return 403 (not 404) for a missing scan",
    (sc.match(/if \(!scan\) return json\(\{ error: "Forbidden" \}, 403\);/g) || []).length >= 2);
  ok("scan report/detail authorize before the R2 read (requireScanReadAccess precedes get)",
    /requireScanReadAccess[\s\S]{0,400}cybermeters_reports\.get/.test(sc));
  // schedule DELETE: nonexistent + foreign collapse to one 403.
  ok("schedule handler collapses nonexistent+foreign to identical 403",
    /if \(!schedule \|\| !scheduleAccess\) return json\(\{ error: "Forbidden" \}, 403\);/.test(sc));
  ok("schedule handler no longer returns a pre-authz 'Schedule not found' 404",
    !/if \(!schedule\) return json\(\{ error: "Schedule not found" \}, 404\);/.test(sc));
  const wc = read("routes/workspaces-core.js");
  ok("workspace restore collapses nonexistent+non-owner to identical 403",
    /if \(!ws \|\| ws\.owner_user_id !== user\.id\) return json\(\{ error: "Forbidden" \}, 403\);/.test(wc));
}

// ── Episode 5A — scheduled catch never downgrades a completed scan ───────────
{
  const idx = read("index.js");
  ok("scheduled-catch D1 write is guarded against downgrading completed",
    /UPDATE scans SET status = 'failed' WHERE id = \? AND status != 'completed'/.test(idx));
  ok("scheduled-catch skips the R2 overwrite when already completed",
    /alreadyCompleted/.test(idx));
}

// ── Episode 5B — detail reconciler converges scan_quality from R2 ────────────
{
  const sc = read("routes/scans.js");
  // Both reconcilers (list + detail) now write scan_quality from raw.scan_quality.
  ok("detail reconciler UPDATE carries scan_quality",
    (sc.match(/UPDATE scans SET status = \?, score = \?, rating = \?, scan_quality = \? WHERE id = \?/g) || []).length >= 2);
  ok("detail reconciler derives scan_quality from the canonical R2 report",
    /correctedQuality = raw\.scan_quality\?\.status/.test(sc));
}

// ── Episode 6 — DMARC ingest fails closed on limiter-store failure ──────────
{
  const gb = read("routes/global-billing.js");
  ok("dmarc-ingest rate limit is fail-closed",
    /"dmarc_ingest", 120, 3600, \{ failClosed: true \}/.test(gb));
  ok("dmarc-ingest distinguishes limiter-unavailable (503) from over-cap (429)",
    /rate_limit_unavailable/.test(gb) && /rl\.status === 503/.test(gb));
}

// ── Episode 7 — dead ungated score-drop sender removed ──────────────────────
{
  const idx = read("index.js");
  ok("dead sendScoreDropAlert is deleted (zero references)", !/sendScoreDropAlert/.test(idx));
  // Active canonical alert path remains, comparable-gated (guarded elsewhere too).
  ok("canonical scan-alert processor remains", /processAlertsForWorkspace/.test(read("engines/alerts.js")));
}

// ── Episode 3 — ONE canonical current-findings scope, shared everywhere ─────
{
  const rq = read("engines/report-queries.js");
  ok("canonical scope is exported", /export const LATEST_COMPLETED_SCAN_SCOPE/.test(rq));
  ok("canonical scope is complete-only + deterministic (id tie-break)",
    /scan_quality = 'complete'/.test(rq) && /ORDER BY sy\.created_at DESC, sy\.id DESC/.test(rq));
  ok("executive-dashboard reuses the canonical scope (no raw 30-day finding window)",
    /LATEST_COMPLETED_SCAN_SCOPE/.test(read("routes/executive-dashboard.js")) &&
    !/f\.severity = 'critical'[\s\S]{0,120}datetime\('now', '-30 days'\)/.test(read("routes/executive-dashboard.js")));
  ok("workspace-insights reuses the canonical scope (no tie-prone MAX join)",
    /LATEST_COMPLETED_SCAN_SCOPE/.test(read("routes/workspace-insights.js")));
  // M5.d: the executive PDF renders canonical snapshots and runs NO scan
  // queries at all — the strongest form of "no inline MAX mirror".
  ok("executive PDF runs no scan queries (snapshot-native)",
    !/FROM scans/.test(read("engines/pdf.js")) &&
    !/SELECT MAX\(sy\.created_at\)/.test(read("engines/pdf.js")));
}

console.log(`\nstabilization-contracts: ${pass} passed, ${fail} failed`);
if (fail) { console.error("stabilization-contracts validation FAILED"); process.exit(1); }
console.log("stabilization-contracts validation passed");
