#!/usr/bin/env node
//
// One-time deployment backfill tool — scans.scan_quality / historical_scores.scan_quality
// ─────────────────────────────────────────────────────────────────────────────
//
// PURPOSE
//   The `scan_quality` columns (scans.scan_quality, historical_scores.scan_quality)
//   were added AFTER many scans had already completed, so legacy rows hold NULL.
//   NULL is correctly treated as 'unknown' by the app (see
//   workers/scan-api/src/engines/assessment-presentation.js → normalizeQuality),
//   but the canonical R2 report for each completed scan DOES record the true
//   coverage quality under `scan_quality.status`. This tool reads that authoritative
//   value from R2 and writes it back into D1 for legacy rows — nothing more.
//
// WHAT THIS IS NOT
//   * NOT a product API, worker route, or scheduled job. It is a hand-run,
//     auditable deployment/ops tool, invoked once from the repo root.
//   * It NEVER infers quality. 'complete' is derived ONLY from a report that
//     literally says so — never from status='completed', from a score/rating,
//     nor from the absence of findings. A missing/malformed/unresolvable report
//     is left NULL (the app already reads NULL as 'unknown').
//
// SAFETY MODEL
//   * FAIL-SAFE DEFAULT: without --apply it runs as a DRY RUN (zero writes).
//     You must pass --apply to write. --dry-run forces dry-run even if --apply
//     is also present.
//   * IDEMPOTENT: every UPDATE carries `AND scan_quality IS NULL`, so re-running
//     never overwrites an already-populated value and is safe to repeat.
//   * NON-DESTRUCTIVE: no DELETE/DROP, and it never rewrites or deletes R2 reports.
//   * The written value is validated against the fixed 4-literal enum
//     (complete|partial|degraded|unknown) BEFORE it is embedded in SQL, so the
//     string interpolation cannot carry anything but a known-safe literal. Scan
//     ids are matched against a strict id pattern before use for the same reason.
//   * PRIVACY: logs contain only scan ids, the derived quality label, and counts.
//     Report bodies / evidence / findings are NEVER printed.
//
// PREREQUISITES
//   * `wrangler` on PATH, authenticated for the CyberMeters Cloudflare account.
//   * Run from the repo root so `workers/scan-api/wrangler.toml` bindings resolve
//     the D1 database (cybermeters-db) and R2 bucket (cybermeters-reports).
//   * Node 24 (ES module, node: builtins only, no external deps).
//
// USAGE
//   node scripts/backfill-scan-quality.js                 # dry-run (default, fail-safe)
//   node scripts/backfill-scan-quality.js --dry-run       # explicit dry-run
//   node scripts/backfill-scan-quality.js --apply         # actually write to D1
//   node scripts/backfill-scan-quality.js --apply --limit 50   # bound the batch
//   node scripts/backfill-scan-quality.js --report out.json    # also write JSON report
//   node scripts/backfill-scan-quality.js --help
//
// FLAGS
//   --apply           Perform D1 writes. Without it, this is a dry run.
//   --dry-run         Force dry-run (overrides --apply). Reads + classifies only.
//   --limit N         Process at most N completed scans (0 = all). Default: all.
//   --report <path>   Also write the reconciliation report as JSON to <path>.
//   -h, --help        Print usage and exit.
//
// The environment variable DRY_RUN=1 is also honoured (forces dry-run).
//
import { execFile } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");

// ── Fixed contracts ───────────────────────────────────────────────────────────
const D1_DATABASE = "cybermeters-db";
const R2_BUCKET = "cybermeters-reports";
const WRANGLER_CONFIG = path.join(root, "workers", "scan-api", "wrangler.toml");

// The ONLY values that may ever be written. Must match normalizeQuality's universe
// in assessment-presentation.js. Anything else → treated as a parse failure → NULL.
const VALID_QUALITY = new Set(["complete", "partial", "degraded", "unknown"]);

// Scan ids are hex/dash-ish identifiers. Reject anything outside a conservative
// safe charset so an unexpected id can never be embedded into SQL or a shell arg.
const SAFE_ID = /^[A-Za-z0-9_-]{1,128}$/;

// Bounded sequential/batch pacing — avoid hammering the API. Small batch size.
const BATCH_SIZE = 4;

// ── CLI parsing ───────────────────────────────────────────────────────────────
function parseArgs(argv) {
  const args = { apply: false, dryRun: false, limit: 0, report: null, help: false };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--apply") args.apply = true;
    else if (a === "--dry-run") args.dryRun = true;
    else if (a === "-h" || a === "--help") args.help = true;
    else if (a === "--limit") { args.limit = Math.max(0, parseInt(argv[++i], 10) || 0); }
    else if (a.startsWith("--limit=")) { args.limit = Math.max(0, parseInt(a.slice(8), 10) || 0); }
    else if (a === "--report") { args.report = argv[++i] ?? null; }
    else if (a.startsWith("--report=")) { args.report = a.slice(9) || null; }
    else { console.error(`Unknown argument: ${a} (use --help)`); process.exit(2); }
  }
  return args;
}

const HELP = `backfill-scan-quality.js — one-time D1 scan_quality backfill from canonical R2 reports

Usage:
  node scripts/backfill-scan-quality.js [--apply] [--dry-run] [--limit N] [--report <path>]

Flags:
  --apply           Perform D1 writes. WITHOUT this flag the tool runs as a DRY RUN.
  --dry-run         Force dry-run (overrides --apply). DRY_RUN=1 env also forces it.
  --limit N         Process at most N completed scans (0 = all). Default: all.
  --report <path>   Also write the reconciliation report as JSON to <path>.
  -h, --help        Show this help.

Fail-safe: dry-run is the default. Idempotent: writes only where scan_quality IS NULL.
Never infers 'complete' — the value comes solely from the R2 report's scan_quality.status.`;

// ── tmp dir (honour $CLAUDE_JOB_DIR/tmp when set) ─────────────────────────────
function resolveTmpDir() {
  const jobDir = process.env.CLAUDE_JOB_DIR;
  if (jobDir && jobDir.trim()) {
    const t = path.join(jobDir.trim(), "tmp");
    try { fs.mkdirSync(t, { recursive: true }); return t; } catch { /* fall through */ }
  }
  return os.tmpdir();
}

// ── wrangler wrappers ─────────────────────────────────────────────────────────
// All wrangler calls go through execFile with an argv array (never a shell string),
// so nothing is shell-interpreted. --config pins the bindings to scan-api.

async function wrangler(subArgs, { maxBuffer = 64 * 1024 * 1024 } = {}) {
  return execFileAsync("wrangler", subArgs, { cwd: root, maxBuffer });
}

// Run a D1 SQL statement remotely, requesting JSON. Returns the parsed rows array
// (first result set) or throws on wrangler failure. Robust to wrangler wrapping the
// JSON in log noise: it extracts the outermost JSON array/object from stdout.
async function d1Json(sql) {
  const { stdout } = await wrangler([
    "d1", "execute", D1_DATABASE,
    "--config", WRANGLER_CONFIG,
    "--remote",
    "--json",
    "--command", sql,
  ]);
  const parsed = extractJson(stdout);
  // wrangler --json returns an array of result-set objects: [{ results:[...], success, meta }]
  if (Array.isArray(parsed)) {
    const first = parsed.find((r) => r && Array.isArray(r.results)) || parsed[0];
    return first && Array.isArray(first.results) ? first.results : [];
  }
  if (parsed && Array.isArray(parsed.results)) return parsed.results;
  return [];
}

// Execute a D1 write statement remotely. No JSON needed; throws on failure.
async function d1Exec(sql) {
  await wrangler([
    "d1", "execute", D1_DATABASE,
    "--config", WRANGLER_CONFIG,
    "--remote",
    "--command", sql,
  ]);
}

// Pull one R2 object to a local temp file, then read+parse it. Returns the parsed
// object, or null if the object is missing / not fetchable / not valid JSON. Always
// cleans up the temp file. Never logs the body.
async function fetchR2Report(scanId, tmpDir) {
  const key = `reports/${scanId}.json`;
  const tmpFile = path.join(tmpDir, `scanq-${scanId}-${process.pid}-${Date.now()}.json`);
  try {
    await wrangler([
      "r2", "object", "get",
      `${R2_BUCKET}/${key}`,
      "--remote",
      "--file", tmpFile,
    ]);
  } catch {
    // Missing object or fetch error — treat as "no report".
    safeUnlink(tmpFile);
    return null;
  }
  try {
    const raw = fs.readFileSync(tmpFile, "utf8");
    return JSON.parse(raw);
  } catch {
    return null; // unreadable / malformed JSON → parse failure
  } finally {
    safeUnlink(tmpFile);
  }
}

function safeUnlink(p) {
  try { fs.unlinkSync(p); } catch { /* already gone */ }
}

// Best-effort extraction of the first top-level JSON value from mixed stdout.
function extractJson(text) {
  const s = String(text || "");
  // Fast path: whole thing is JSON.
  try { return JSON.parse(s); } catch { /* fall through to scan */ }
  const start = s.search(/[[{]/);
  if (start === -1) return null;
  const open = s[start];
  const close = open === "[" ? "]" : "}";
  let depth = 0, inStr = false, esc = false;
  for (let i = start; i < s.length; i++) {
    const c = s[i];
    if (inStr) {
      if (esc) esc = false;
      else if (c === "\\") esc = true;
      else if (c === '"') inStr = false;
      continue;
    }
    if (c === '"') inStr = true;
    else if (c === open) depth++;
    else if (c === close) { depth--; if (depth === 0) { try { return JSON.parse(s.slice(start, i + 1)); } catch { return null; } } }
  }
  return null;
}

// ── Quality derivation (STRICT — no inference) ────────────────────────────────
// Returns one of the 4 valid literals ONLY when the report literally carries a
// recognised scan_quality.status. Otherwise returns null (→ leave D1 NULL). We do
// NOT map missing/absent status to 'unknown' as a WRITE — NULL already reads as
// 'unknown' downstream, and writing nothing keeps the backfill honest and re-runnable.
function deriveQuality(report) {
  if (!report || typeof report !== "object") return { quality: null, reason: "no_report" };
  const sq = report.scan_quality;
  if (!sq || typeof sq !== "object" || sq.status == null) {
    return { quality: null, reason: "no_status_field" };
  }
  const normalized = String(sq.status).trim().toLowerCase();
  if (!VALID_QUALITY.has(normalized)) {
    return { quality: null, reason: "unrecognised_status" };
  }
  return { quality: normalized, reason: "ok" };
}

// ── Main ──────────────────────────────────────────────────────────────────────
async function main() {
  const args = parseArgs(process.argv.slice(2));
  if (args.help) { console.log(HELP); return; }

  // Fail-safe: dry-run unless --apply is given; --dry-run / DRY_RUN=1 force it.
  const forceDry = args.dryRun || process.env.DRY_RUN === "1";
  const apply = args.apply && !forceDry;
  const mode = apply ? "APPLY (writes enabled)" : "DRY-RUN (no writes)";

  const tmpDir = resolveTmpDir();

  console.log("── backfill-scan-quality ─────────────────────────────────────");
  console.log(`Mode:        ${mode}`);
  console.log(`Database:    ${D1_DATABASE} (remote)`);
  console.log(`Bucket:      ${R2_BUCKET} (remote)`);
  console.log(`Temp dir:    ${tmpDir}`);
  if (args.limit) console.log(`Limit:       ${args.limit} scans`);
  if (!apply && args.apply && forceDry) console.log("Note:        --apply present but overridden by dry-run.");
  console.log("──────────────────────────────────────────────────────────────");

  // 1. Completed scan ids from D1.
  let rows;
  try {
    rows = await d1Json("SELECT id FROM scans WHERE status='completed'");
  } catch (e) {
    console.error(`FATAL: could not query completed scans from D1: ${e.message}`);
    process.exit(1);
  }

  let scanIds = rows
    .map((r) => (r && r.id != null ? String(r.id) : null))
    .filter((id) => id && SAFE_ID.test(id));
  const rejectedIds = rows.length - scanIds.length;
  if (args.limit > 0) scanIds = scanIds.slice(0, args.limit);

  console.log(`Completed scans returned by D1: ${rows.length}` +
    (rejectedIds ? ` (${rejectedIds} rejected by id safety pattern)` : "") +
    (args.limit ? ` — processing ${scanIds.length}` : ""));

  // 2–7. Per-scan: fetch report, derive quality, (optionally) write D1.
  const stats = {
    scans_inspected: 0,
    r2_reports_found: 0,
    complete: 0,
    partial: 0,
    degraded: 0,
    unknown: 0,           // valid literal 'unknown' seen in a report
    null_left: 0,         // left NULL (no valid quality derived)
    parse_failures: 0,    // report existed but status unusable/malformed
    missing_reports: 0,   // no R2 report at all
    fetch_errors: 0,      // wrangler error fetching a report (counted as missing)
    scans_updated: 0,     // scans rows we wrote (or would-write in dry-run)
    scans_already_set: 0, // guarded no-op (already non-NULL) — approximated by write attempt
    historical_updated: 0,// historical_scores rows written (or would-write)
    historical_errors: 0, // write errors on historical_scores
    scan_write_errors: 0, // write errors on scans
  };
  const rejectedSample = [];

  for (let i = 0; i < scanIds.length; i += BATCH_SIZE) {
    const batch = scanIds.slice(i, i + BATCH_SIZE);
    await Promise.all(batch.map((id) => processScan(id, { apply, tmpDir, stats, rejectedSample })));
    // Light pacing between batches.
    if (i + BATCH_SIZE < scanIds.length) await sleep(50);
  }

  // 10. Reconciliation report.
  const report = {
    generated_at: new Date().toISOString(),
    mode: apply ? "apply" : "dry-run",
    database: D1_DATABASE,
    bucket: R2_BUCKET,
    limit: args.limit || null,
    d1_completed_scans_returned: rows.length,
    d1_ids_rejected_by_pattern: rejectedIds,
    ...stats,
    rejected_status_sample: rejectedSample.slice(0, 20),
  };

  printReconciliation(report, apply);

  if (args.report) {
    try {
      fs.writeFileSync(args.report, JSON.stringify(report, null, 2));
      console.log(`\nJSON reconciliation written to: ${path.resolve(args.report)}`);
    } catch (e) {
      console.error(`WARN: could not write --report file: ${e.message}`);
    }
  }
}

async function processScan(id, { apply, tmpDir, stats, rejectedSample }) {
  stats.scans_inspected++;
  let report;
  try {
    report = await fetchR2Report(id, tmpDir);
  } catch {
    stats.fetch_errors++;
    stats.missing_reports++;
    stats.null_left++;
    return;
  }
  if (report === null) {
    // Distinguish missing vs malformed is hard here (fetchR2Report returns null for
    // both); count as missing report and leave NULL.
    stats.missing_reports++;
    stats.null_left++;
    return;
  }
  stats.r2_reports_found++;

  const { quality, reason } = deriveQuality(report);
  if (!quality) {
    if (reason === "unrecognised_status") {
      stats.parse_failures++;
      // Record a small, non-sensitive sample of the offending status string.
      const raw = report?.scan_quality?.status;
      if (raw != null && rejectedSample.length < 20) {
        rejectedSample.push({ scan_id: id, status: String(raw).slice(0, 40) });
      }
    } else {
      // no_status_field / no_report → treated as a parse failure to leave NULL.
      stats.parse_failures++;
    }
    stats.null_left++;
    return;
  }

  // Tally by class.
  stats[quality]++;

  // Defence in depth: the value MUST be one of the 4 literals before embedding.
  if (!VALID_QUALITY.has(quality)) {
    stats.parse_failures++;
    stats.null_left++;
    return;
  }

  // 5 + 6. Idempotent, guarded UPDATEs (only where still NULL).
  const scanSql =
    `UPDATE scans SET scan_quality='${quality}' WHERE id='${id}' AND scan_quality IS NULL`;
  const histSql =
    `UPDATE historical_scores SET scan_quality='${quality}' WHERE scan_id='${id}' AND scan_quality IS NULL`;

  if (!apply) {
    // Dry-run: report the intent, write nothing.
    console.log(`[dry-run] ${id} → ${quality} (would UPDATE scans + historical_scores where NULL)`);
    stats.scans_updated++;
    stats.historical_updated++;
    return;
  }

  try {
    await d1Exec(scanSql);
    stats.scans_updated++;
    console.log(`[apply] ${id} → ${quality} (scans updated where NULL)`);
  } catch (e) {
    stats.scan_write_errors++;
    console.error(`[apply] ${id} → scans UPDATE FAILED: ${e.message.split("\n")[0]}`);
  }

  try {
    await d1Exec(histSql);
    stats.historical_updated++;
  } catch (e) {
    stats.historical_errors++;
    console.error(`[apply] ${id} → historical_scores UPDATE FAILED: ${e.message.split("\n")[0]}`);
  }
}

function printReconciliation(r, apply) {
  const verb = apply ? "updated" : "would update";
  console.log("\n── Reconciliation ────────────────────────────────────────────");
  console.log(`Mode:                         ${r.mode}`);
  console.log(`Scans inspected:              ${r.scans_inspected}`);
  console.log(`R2 reports found:             ${r.r2_reports_found}`);
  console.log(`Missing reports (left NULL):  ${r.missing_reports}` +
    (r.fetch_errors ? ` (incl. ${r.fetch_errors} fetch errors)` : ""));
  console.log(`Parse failures (left NULL):   ${r.parse_failures}`);
  console.log("  ── derived quality ──");
  console.log(`  complete:                   ${r.complete}`);
  console.log(`  partial:                    ${r.partial}`);
  console.log(`  degraded:                   ${r.degraded}`);
  console.log(`  unknown (explicit):         ${r.unknown}`);
  console.log(`  left NULL (no valid value): ${r.null_left}`);
  console.log("  ── writes ──");
  console.log(`  scans ${verb}:              ${r.scans_updated}` +
    (r.scan_write_errors ? ` (${r.scan_write_errors} errors)` : ""));
  console.log(`  historical_scores ${verb}:  ${r.historical_updated}` +
    (r.historical_errors ? ` (${r.historical_errors} errors)` : ""));
  console.log("──────────────────────────────────────────────────────────────");
  if (!apply) {
    console.log("DRY RUN — no rows were written. Re-run with --apply to persist.");
  } else {
    console.log("APPLY complete. Re-running is safe (guarded by scan_quality IS NULL).");
  }
}

const sleep = (ms) => new Promise((res) => setTimeout(res, ms));

main().catch((e) => {
  console.error(`FATAL: ${e && e.message ? e.message : e}`);
  process.exit(1);
});
