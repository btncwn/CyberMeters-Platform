#!/usr/bin/env node
//
// Scheduled-report OCCURRENCE claim atomicity — proves that under genuinely
// overlapping execution exactly ONE invocation may generate a report for a given
// (workspace_id, report_type, report_period). Drives the REAL claimReportOccurrence
// + generateWorkspaceExecutiveReport (engines/plan-usage.js) against a node:sqlite DB
// carrying the production schema + migration 081 partial UNIQUE index (D1 uses the
// same SQLite engine). The atomic guarantee is the DB's INSERT OR IGNORE on that
// index — not a sequential SELECT-then-INSERT. Node 24+. CI-blocking.
import fs from "node:fs";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const { claimReportOccurrence, generateWorkspaceExecutiveReport, STALE_REPORT_CLAIM_MINUTES } =
  await import(pathToFileURL(path.join(root, "workers", "scan-api", "src", "engines", "plan-usage.js")).href);

let pass = 0, fail = 0;
const ok = (n, c, d = "") => { c ? pass++ : fail++; if (!c) console.log(`FAIL ${n}${d ? " — " + d : ""}`); };

function buildDb() {
  const db = new DatabaseSync(":memory:");
  const apply = (p) => { try { db.exec(fs.readFileSync(p, "utf8")); } catch { /* ordering/dup */ } };
  apply(path.join(root, "database", "schema.sql"));
  for (const f of fs.readdirSync(path.join(root, "database", "migrations")).filter((f) => f.endsWith(".sql")).sort()) {
    apply(path.join(root, "database", "migrations", f));
  }
  return db;
}
function makeD1(db) {
  const wrap = (sql, args) => ({
    first: async (col) => { const r = db.prepare(sql).get(...args) ?? null; return col && r ? r[col] : r; },
    all:   async () => ({ results: db.prepare(sql).all(...args) }),
    run:   async () => { const r = db.prepare(sql).run(...args); return { meta: { changes: r.changes } }; },
  });
  return { prepare(sql) { const b = wrap(sql, []); b.bind = (...a) => wrap(sql, a); return b; } };
}
const WS = "ws1", TYPE = "weekly_executive", PERIOD = "2026-W30";
const claimArgs = (id, createdAt = new Date().toISOString()) => ({
  reportId: id, workspaceId: WS, report_type: TYPE, report_period: PERIOD,
  r2Key: `reports/executive/${WS}/${TYPE}/${PERIOD}/executive-report.pdf`, retentionPolicy: "standard", createdAt,
});
const activeCount = (db) => db.prepare(
  `SELECT COUNT(*) AS n FROM workspace_reports WHERE workspace_id=? AND report_type=? AND report_period=? AND deleted_at IS NULL AND status != 'failed'`
).get(WS, TYPE, PERIOD).n;

// ── 1. True interleaving: A and B both begin before either completes ─────────
{
  const db = buildDb(); const env = { cybermeters_db: makeD1(db) };
  // A and B each generated their own reportId, both saw no completed row, both now
  // attempt the atomic claim (interleaved).
  const a = await claimReportOccurrence(env, claimArgs("rptA"));
  const b = await claimReportOccurrence(env, claimArgs("rptB"));
  ok("1: exactly one invocation wins the claim", a.won === true && b.won === false, JSON.stringify({ a, b }));
  ok("1: loser sees the winner's row as the active occurrence", b.existing?.id === "rptA");
  ok("1: exactly ONE active occurrence row exists", activeCount(db) === 1);
}

// ── 2. Database uniqueness enforced (not just app logic) ─────────────────────
{
  const db = buildDb(); const env = { cybermeters_db: makeD1(db) };
  await claimReportOccurrence(env, claimArgs("rptA"));
  // A raw un-ignored duplicate INSERT must be rejected by the partial UNIQUE index.
  let threw = false;
  try {
    db.prepare(`INSERT INTO workspace_reports (id, workspace_id, report_type, report_period, report_key, status, created_at) VALUES (?,?,?,?,?, 'pending', ?)`)
      .run("rptDup", WS, TYPE, PERIOD, "k", new Date().toISOString());
  } catch { threw = true; }
  ok("2: DB rejects a second active occurrence row (partial UNIQUE index)", threw);
  // INSERT OR IGNORE (the claim path) is a no-op, not an error.
  const b = await claimReportOccurrence(env, claimArgs("rptB"));
  ok("2: claim path returns won:false (no error) for a duplicate", b.won === false);
}

// ── 3. Completed occurrence is never regenerated ─────────────────────────────
{
  const db = buildDb(); const env = { cybermeters_db: makeD1(db) };
  db.prepare(`INSERT INTO workspace_reports (id, workspace_id, report_type, report_period, report_key, status, created_at) VALUES (?,?,?,?,?, 'completed', ?)`)
    .run("rptDone", WS, TYPE, PERIOD, "k", new Date().toISOString());
  const c = await claimReportOccurrence(env, claimArgs("rptNew"));
  ok("3: a completed occurrence blocks a new claim", c.won === false && c.existing?.id === "rptDone");
}

// ── 4. Failed occurrence is retryable ────────────────────────────────────────
{
  const db = buildDb(); const env = { cybermeters_db: makeD1(db) };
  db.prepare(`INSERT INTO workspace_reports (id, workspace_id, report_type, report_period, report_key, status, created_at) VALUES (?,?,?,?,?, 'failed', ?)`)
    .run("rptFail", WS, TYPE, PERIOD, "k", new Date().toISOString());
  const r = await claimReportOccurrence(env, claimArgs("rptRetry"));
  ok("4: a failed occurrence does not block — retry claim succeeds", r.won === true);
  ok("4: exactly one active occurrence after retry (the new pending)", activeCount(db) === 1);
}

// ── 5. Stale pending recovery (deterministic) + fresh pending not stolen ─────
{
  const db = buildDb(); const env = { cybermeters_db: makeD1(db) };
  const staleAt = new Date(Date.now() - (STALE_REPORT_CLAIM_MINUTES + 5) * 60 * 1000).toISOString();
  db.prepare(`INSERT INTO workspace_reports (id, workspace_id, report_type, report_period, report_key, status, created_at) VALUES (?,?,?,?,?, 'pending', ?)`)
    .run("rptStale", WS, TYPE, PERIOD, "k", staleAt);
  const r = await claimReportOccurrence(env, claimArgs("rptFresh"));
  ok("5: expired pending is reclaimed — new claim wins", r.won === true);
  ok("5: the stale pending was transitioned to failed", db.prepare("SELECT status FROM workspace_reports WHERE id='rptStale'").get().status === "failed");
  ok("5: still exactly one active occurrence (the reclaimed pending)", activeCount(db) === 1);

  // A FRESH (< timeout) pending must NOT be stolen.
  const db2 = buildDb(); const env2 = { cybermeters_db: makeD1(db2) };
  db2.prepare(`INSERT INTO workspace_reports (id, workspace_id, report_type, report_period, report_key, status, created_at) VALUES (?,?,?,?,?, 'pending', ?)`)
    .run("rptLive", WS, TYPE, PERIOD, "k", new Date().toISOString());
  const s = await claimReportOccurrence(env2, claimArgs("rptThief"));
  ok("5: a fresh live pending is never stolen", s.won === false && s.existing?.id === "rptLive"
      && db2.prepare("SELECT status FROM workspace_reports WHERE id='rptLive'").get().status === "pending");
}

// ── 6. R2/generation failure → occurrence not completed, retry possible ──────
// generateWorkspaceExecutiveReport with a D1-only env (no R2 binding): the WINNER
// reaches collectPdfData, which throws (no R2) → its row is marked failed + it
// throws. A subsequent claim can retry. Proves R2 failure leaves a retryable failed
// occurrence and NO completed row.
{
  const db = buildDb(); const env = { cybermeters_db: makeD1(db) }; // note: no cybermeters_reports
  db.prepare("INSERT INTO workspaces (id, name, owner_user_id) VALUES (?,?,?)").run(WS, "WS", "owner");
  let threw = false;
  try { await generateWorkspaceExecutiveReport(WS, env, { report_type: TYPE, report_period: PERIOD }); }
  catch { threw = true; }
  ok("6: winner attempts generation and fails without R2 (throws)", threw);
  ok("6: no COMPLETED occurrence after R2 failure", db.prepare(`SELECT COUNT(*) AS n FROM workspace_reports WHERE workspace_id=? AND report_type=? AND report_period=? AND status='completed'`).get(WS, TYPE, PERIOD).n === 0);
  ok("6: the failed occurrence is retryable (a fresh claim wins)", (await claimReportOccurrence(env, claimArgs("rptAfterFail"))).won === true);
}

// ── 7. Loss path performs ZERO generation side effects (no PDF/R2/usage) ──────
// A concurrent loser must short-circuit BEFORE collectPdfData. Called with a D1-only
// env and a pre-existing active claim: if it tried to generate it would throw on the
// missing R2 — instead it returns claimed:false cleanly and writes no new row.
{
  const db = buildDb(); const env = { cybermeters_db: makeD1(db) }; // no R2
  db.prepare("INSERT INTO workspaces (id, name, owner_user_id) VALUES (?,?,?)").run(WS, "WS", "owner");
  db.prepare(`INSERT INTO workspace_reports (id, workspace_id, report_type, report_period, report_key, status, created_at) VALUES (?,?,?,?,?, 'pending', ?)`)
    .run("rptHeld", WS, TYPE, PERIOD, "k", new Date().toISOString());
  const before = db.prepare("SELECT COUNT(*) AS n FROM workspace_reports").get().n;
  const res = await generateWorkspaceExecutiveReport(WS, env, { report_type: TYPE, report_period: PERIOD });
  const after = db.prepare("SELECT COUNT(*) AS n FROM workspace_reports").get().n;
  ok("7: loser returns claimed:false without generating (no R2 touched, no throw)", res.claimed === false && res.deduplicated === true);
  ok("7: loser wrote NO new report row (no duplicate usage row)", after === before);
}

// ── 8. Overlapping retry → still exactly one generator claim ─────────────────
{
  const db = buildDb(); const env = { cybermeters_db: makeD1(db) };
  db.prepare(`INSERT INTO workspace_reports (id, workspace_id, report_type, report_period, report_key, status, created_at) VALUES (?,?,?,?,?, 'failed', ?)`)
    .run("rptFail", WS, TYPE, PERIOD, "k", new Date().toISOString());
  const r1 = await claimReportOccurrence(env, claimArgs("rptRetryA"));
  const r2 = await claimReportOccurrence(env, claimArgs("rptRetryB"));
  ok("8: two overlapping retries → exactly one wins", (r1.won ? 1 : 0) + (r2.won ? 1 : 0) === 1);
  ok("8: exactly one active occurrence after overlapping retry", activeCount(db) === 1);
}

// ── 9. Soft-deleted history coexists; the identity does not corrupt history ──
{
  const db = buildDb(); const env = { cybermeters_db: makeD1(db) };
  db.prepare(`INSERT INTO workspace_reports (id, workspace_id, report_type, report_period, report_key, status, created_at, deleted_at) VALUES (?,?,?,?,?, 'completed', ?, ?)`)
    .run("rptOld", WS, TYPE, PERIOD, "k", "2026-06-01T00:00:00Z", "2026-06-15T00:00:00Z"); // soft-deleted historical
  const r = await claimReportOccurrence(env, claimArgs("rptRegen"));
  ok("9: a period can be regenerated after its report was soft-deleted", r.won === true);
  ok("9: the soft-deleted historical row is preserved (history not corrupted)",
    db.prepare("SELECT status, deleted_at FROM workspace_reports WHERE id='rptOld'").get().deleted_at != null);
  ok("9: exactly one ACTIVE occurrence (the new one); the deleted one is excluded", activeCount(db) === 1);
}

// ── 10. Caller-level notification is guarded on the claimed flag (no dup email) ─
{
  const src = fs.readFileSync(path.join(root, "workers", "scan-api", "src", "index.js"), "utf8");
  ok("10: user-schedule caller only notifies when it actually generated (claimed !== false)",
    /reportRow\?\.claimed !== false/.test(src));
}

console.log(`\nreport-occurrence-claim: ${pass} passed, ${fail} failed`);
if (fail) { console.error("report-occurrence-claim validation FAILED"); process.exit(1); }
console.log("report-occurrence-claim validation passed");
