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

// ── Episode 5B — scan-lifecycle persistence contracts (PR-1, 22 Jul 2026) ────
// Durable D1↔R2 convergence moved to the ONE canonical cron recovery engine;
// GET list/detail became read-only display. Five contracts, founder-specified:
//   1. detail/list reconciliation performs NO DB mutation;
//   2. terminal finalisation still persists scan_quality;
//   3. interrupted recovery EXPLICITLY persists scan_quality = NULL;
//   4. the recovery UPDATE is guarded and cron/internal-only;
//   5. any reintroduced GET-side UPDATE fails here (contract 1's direction).
{
  const sc = read("routes/scans.js");

  // (1)+(5) The two display-correction blocks are mutation-free, and the whole
  // route file carries ZERO scans-mutating statements. The block-scoped check
  // makes a reintroduced write INSIDE a reconciler fail even if someone also
  // renames things; the file-scoped check catches it anywhere else.
  const markers = sc.split("Stuck-scan DISPLAY correction (read-only)");
  ok("both GET display-correction blocks exist (list + detail)", markers.length === 3);
  for (let i = 1; i < markers.length; i++) {
    const block = markers[i].slice(0, 3200); // the full reconciler block body
    ok(`display-correction block ${i} performs no DB mutation (no INSERT/UPDATE/DELETE)`,
      !/\b(INSERT\s+INTO|UPDATE\s+\w+\s+SET|DELETE\s+FROM)\b/i.test(block));
  }
  ok("routes/scans.js contains zero UPDATE/DELETE against scans",
    !/UPDATE\s+scans/i.test(sc) && !/DELETE\s+FROM\s+scans/i.test(sc));

  // (2) Terminal finalisation still persists scan_quality (canonical writer).
  const se = read("engines/scan-engine.js");
  ok("finalisation persists scan_quality in its D1 UPDATE",
    /UPDATE scans SET status = \?, score = \?, rating = \?, scan_quality = \?/.test(se));

  // (3) Interrupted recovery explicitly persists scan_quality = NULL.
  const rec = read("engines/scan-recovery.js");
  ok("interrupted recovery explicitly persists scan_quality = NULL",
    /UPDATE scans SET status = 'failed', scan_quality = NULL/.test(rec));

  // Convergence-from-R2 invariant stays pinned at the canonical site.
  ok("canonical recovery converges scan_quality from the SAME R2 report",
    /UPDATE scans SET status = \?, score = \?, rating = \?, scan_quality = \?/.test(rec) &&
    /raw\.scan_quality\?\.status/.test(rec));
  ok("detail display correction derives scan_quality from the canonical R2 report",
    /correctedQuality = raw\.scan_quality\?\.status/.test(sc));

  // (4) Recovery is guarded (racing finalisation wins) and cron/internal-only:
  // registered in the cron orchestrator, imported by index.js, and by NO route.
  ok("recovery UPDATE is guarded by AND status IN (racing finalisation wins)",
    /status = 'failed', scan_quality = NULL\s*\n?\s*WHERE id = \? AND status IN/.test(rec));
  const cron = read("cron/scheduled.js");
  ok("recovery is registered as a cron task", /recoverInterruptedScans/.test(cron));

  // PR-1b (22 Jul 2026) — canonical quality invariant: a running or interrupted
  // scan has NOT earned `complete` or `partial`.
  ok("running START placeholder carries scan_quality = null (no hardcoded quality)",
    /const initialScanQuality = null/.test(sc) && !/initialScanQuality = \{/.test(sc));
  ok("interrupted failed R2 report explicitly nulls scan_quality after the spread",
    /message: INTERRUPTED_CUSTOMER_MESSAGE,[\s\S]{0,500}scan_quality: null/.test(rec));
  const routeFiles = fs.readdirSync(path.join(S, "routes")).filter((f) => f.endsWith(".js"));
  const routeImports = routeFiles.filter((f) =>
    /import[^;]*from\s+["'][^"']*scan-recovery/.test(read(`routes/${f}`)));
  ok("no route imports the recovery engine (cron/internal-only)",
    routeImports.length === 0, routeImports.join(","));
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
