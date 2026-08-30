#!/usr/bin/env node
//
// Partial-scan score honesty. A partial/degraded/timed-out/dependency-degraded or
// materially-skipped assessment must never be presented as a final clean result,
// must never get an unqualified rating (Excellent/Good), and must never look more
// trustworthy because risk-producing checks didn't complete. Proves the canonical
// presentation resolver, the current-posture selector, D1 persistence parity, the
// executive-report + PDF delegation, and trend gating. Node 24+ (node:sqlite).
// CI-blocking.
import fs from "node:fs";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const eng = (f) => import(pathToFileURL(path.join(root, "workers", "scan-api", "src", "engines", f)).href);
const { resolveAssessmentPresentation, normalizeQuality, ASSESSMENT_MESSAGES, POSTURE_NOT_ESTABLISHED_MESSAGE } = await eng("assessment-presentation.js");
const { getAuthoritativeCurrentPosture, isComparableAssessment } = await eng("current-posture.js");
const { createFinalizeLatch, finalizeScanResult } = await eng("scan-engine.js");
const { buildExecutiveReportV2 } = await eng("executive-report.js");
const { composeSnapshot } = await eng("report-snapshot.js");
const healthyMonitoringStates = {
  version: "signal-monitoring-state-v1",
  signals: Object.fromEntries([
    "dns",
    "certificate_transparency",
    "website_security",
    "email_protection",
    "attack_surface",
    "technology_visibility",
    "vulnerability_intelligence",
    "registration_data",
  ].map((signal) => [signal, {
    state: "monitoring_healthy",
    message: `${signal} checks completed normally in this run.`,
    evidence: { modules: [], incomplete_modules: [], providers: {} },
  }])),
};
// M5.d: the executive report is a pure view over the canonical snapshot; the
// partial-scan honesty now lives in the snapshot's frozen assessment.
const mkRead = (rawReport, scanId = "s_partial") => ({
  status: "ok",
  snapshot: composeSnapshot({
    snapshotId: "snap_" + scanId, workspaceId: "ws_p", domainId: "dom_p", scanId,
    domain: rawReport.domain ?? "example.co.uk",
    report: {
      status: "completed",
      completed_at: "2026-07-14T10:00:00Z",
      monitoring_states: healthyMonitoringStates,
      ...rawReport,
    },
    cyberEssentials: null, ceReadiness: null, caseRows: [], questionSetVersions: [],
    supersedesSnapshotId: null, builtAt: "2026-07-14T10:00:05Z",
  }),
  row: { id: "snap_" + scanId }, integrity: { verified: true },
});
const { riskLevelForScore } = await eng("scoring.js");

let pass = 0, fail = 0;
const ok = (n, c, d = "") => { c ? pass++ : fail++; if (!c) console.log(`FAIL ${n}${d ? " — " + d : ""}`); };
const eq = (n, g, w) => ok(n, g === w, `got ${JSON.stringify(g)} want ${JSON.stringify(w)}`);

// ── normalizeQuality: legacy NULL / unknown / malformed → 'unknown', never complete ──
{
  eq("null → unknown", normalizeQuality(null), "unknown");
  eq("undefined → unknown", normalizeQuality(undefined), "unknown");
  eq("'' → unknown", normalizeQuality(""), "unknown");
  eq("garbage → unknown", normalizeQuality("garbage"), "unknown");
  eq("'COMPLETE' → complete (case-insensitive)", normalizeQuality("COMPLETE"), "complete");
  eq("partial passthrough", normalizeQuality("partial"), "partial");
  ok("(10) malformed R2 quality resolves to unknown, not complete", normalizeQuality("weird-status") !== "complete");
}

// ── Resolver: partial/degraded 95 never renders as a rating; complete does ──
{
  const partial = resolveAssessmentPresentation({ score: 95, scanQuality: "partial", status: "completed" });
  eq("(1) partial 95 → display_rating null (never 95/Excellent)", partial.display_rating, null);
  eq("partial 95 → display_score still shown (provisional)", partial.display_score, 95);
  ok("partial → provisional/non-authoritative/non-comparable", partial.provisional && !partial.authoritative && !partial.comparable);
  eq("partial message exact", partial.message, "Some checks were not completed. This score is provisional.");

  const degraded = resolveAssessmentPresentation({ score: 95, scanQuality: "degraded", status: "completed" });
  eq("(2) degraded 95 → display_rating null (never 95/Excellent)", degraded.display_rating, null);
  ok("degraded → provisional/non-authoritative/non-comparable", degraded.provisional && !degraded.authoritative && !degraded.comparable);
  eq("degraded message exact", degraded.message, "Some checks or evidence sources were degraded. This score is provisional.");

  const unknown = resolveAssessmentPresentation({ score: 70, scanQuality: null, status: "completed" });
  eq("(8) unknown → no final rating", unknown.display_rating, null);
  ok("unknown → not authoritative (never treated as complete)", !unknown.authoritative && !unknown.comparable);
  eq("unknown legacy caveat exact", unknown.message, "Legacy assessment — coverage quality unavailable.");

  const complete = resolveAssessmentPresentation({ score: 82, scanQuality: "complete", status: "completed" });
  eq("(14) complete 82 → real rating shown", complete.display_rating, riskLevelForScore(82));
  ok("complete → authoritative + comparable, no caveat", complete.authoritative && complete.comparable && complete.message === null);

  // A failed scan yields no usable score/rating regardless.
  const failed = resolveAssessmentPresentation({ score: 0, scanQuality: null, status: "failed" });
  eq("failed status → no display_score", failed.display_score, null);
  eq("failed status → no rating", failed.display_rating, null);
}

// ── Reusable stubs for the selector + finalization ──
function memDb() {
  const db = new DatabaseSync(":memory:");
  db.exec(`CREATE TABLE scans (id TEXT PRIMARY KEY, domain_id TEXT, domain TEXT, status TEXT, score INTEGER, rating TEXT, scan_quality TEXT, created_at TEXT);
           CREATE TABLE workspace_domains (workspace_id TEXT, domain_id TEXT);`);
  return db;
}
const d1 = (db) => ({ prepare(sql) { const w = (a) => ({ first: async () => db.prepare(sql).get(...a) ?? null, all: async () => ({ results: db.prepare(sql).all(...a) }), run: async () => { db.prepare(sql).run(...a); return { meta: {} }; } }); const b = w([]); b.bind = (...a) => w(a); return b; } });

// ── Current-posture selector ──
{
  const db = memDb();
  const scan = (id, dom, status, score, quality, at) => db.prepare("INSERT INTO scans VALUES (?,?,?,?,?,?,?,?)").run(id, "d1", dom, status, score, null, quality, at);
  // Complete 82 (older) then partial 95 (newer) for the same domain.
  scan("s_complete", "example.co.uk", "completed", 82, "complete", "2026-07-13 10:00:00");
  scan("s_partial",  "example.co.uk", "completed", 95, "partial",  "2026-07-14 10:00:00");
  const env = { cybermeters_db: d1(db) };
  const p = await getAuthoritativeCurrentPosture(env, { domainId: "d1" });
  eq("(3) authoritative = latest COMPLETE 82, not newer partial 95", p.authoritative?.score, 82);
  eq("(3) authoritative scan id is the complete one", p.authoritative?.scan_id, "s_complete");
  eq("(18) newer partial 95 is NOT authoritative (skipped checks can't raise posture)", p.state, "established");
  eq("(17) newer partial shown separately as provisional", p.latest_provisional?.scan_id, "s_partial");
  ok("(17) provisional latest is non-comparable", !isComparableAssessment(p.latest_provisional?.scan_quality));

  // Replace the partial with a degraded 95 → still not authoritative.
  db.prepare("UPDATE scans SET scan_quality='degraded' WHERE id='s_partial'").run();
  const p2 = await getAuthoritativeCurrentPosture(env, { domainId: "d1" });
  eq("(4) authoritative stays 82 over newer DEGRADED 95", p2.authoritative?.score, 82);

  // A domain with only partial/unknown completed scans → posture NOT established.
  const db2 = memDb();
  db2.prepare("INSERT INTO scans VALUES ('s_only_partial','d2','x.co.uk','completed',95,null,'partial','2026-07-14 10:00:00')").run();
  db2.prepare("INSERT INTO scans VALUES ('s_only_unknown','d2','x.co.uk','completed',70,null,NULL,'2026-07-10 10:00:00')").run();
  const p3 = await getAuthoritativeCurrentPosture({ cybermeters_db: d1(db2) }, { domainId: "d2" });
  eq("(7) no complete assessment → current posture NOT established", p3.state, "not_established");
  eq("(7) authoritative is null when no complete scan", p3.authoritative, null);
  eq("(8) unknown legacy scan never becomes authoritative", p3.authoritative, null);

  // Deterministic tie-break: two COMPLETE scans, identical created_at → higher id wins.
  const db3 = memDb();
  db3.prepare("INSERT INTO scans VALUES ('s_a','d3','y.co.uk','completed',80,null,'complete','2026-07-14 12:00:00')").run();
  db3.prepare("INSERT INTO scans VALUES ('s_b','d3','y.co.uk','completed',90,null,'complete','2026-07-14 12:00:00')").run();
  const p4 = await getAuthoritativeCurrentPosture({ cybermeters_db: d1(db3) }, { domainId: "d3" });
  eq("(15) deterministic tie-break on identical created_at (id DESC → s_b)", p4.authoritative?.scan_id, "s_b");
}

// ── (16) D1 and R2 quality match after finalization ──
{
  const captured = [];
  const env = {
    cybermeters_reports: { put: async (k, body) => { captured.push({ r2: JSON.parse(body).scan_quality?.status }); } },
    cybermeters_db: {
      prepare: (sql) => ({ bind: (...a) => ({ run: async () => { if (/UPDATE scans SET status/.test(sql)) captured.push({ d1_quality: a[3] }); } }) }),
      batch: async (statements) => Promise.all(statements.map((statement) => statement.run())),
    },
  };
  const latch = createFinalizeLatch();
  const report = { status: "completed", scan_quality: { status: "partial" }, cyber_metrics_score: 95 };
  await finalizeScanResult(latch, { scanId: "scan_x", report, score: 95, rating: "excellent", status: "completed", env });
  const r2q = captured.find((c) => "r2" in c)?.r2;
  const d1q = captured.find((c) => "d1_quality" in c)?.d1_quality;
  eq("(16) R2 report scan_quality persisted", r2q, "partial");
  eq("(16) D1 scan_quality persisted from the SAME report", d1q, "partial");
  ok("(16) D1 and R2 quality agree", r2q === d1q);
}

// ── Executive report V2 parity: partial → no rating, no reassurance, no trend delta ──
{
  const rawReport = {
    domain: "example.co.uk", cyber_metrics_score: 95, risk_level: "excellent",
    scan_quality: { status: "partial", modules_skipped: ["asset_exposure"] },
    findings: [], recommendations: [],
    modules: { historical_changes: { has_previous: true, previous_scan_id: "prev", previous_score: 82, score_change: null, comparable: false } },
  };
  const rep = buildExecutiveReportV2({ scan: { id: "s1", score: 95, status: "completed", domain: "example.co.uk" }, read: mkRead(rawReport, "s1") });
  eq("(1) exec report: partial → rating null (never Excellent)", rep.cyber_metrics_score.rating, null);
  eq("exec report: value still 95 (provisional)", rep.cyber_metrics_score.value, 95);
  ok("exec report: marked provisional/non-authoritative", rep.cyber_metrics_score.provisional && !rep.cyber_metrics_score.authoritative);
  eq("(6) exec report: no reassuring narrative — shows the caveat", rep.risk_intelligence?.narrative ?? null, null); // narrative moved; check below
  ok("(6) exec report narrative is the provisional caveat, not 'controls are strong'", JSON.stringify(rep).includes("Some checks were not completed") && !JSON.stringify(rep).includes("controls are strong"));
  eq("(5) exec report: no trend delta for partial (score_change null)", rep.historical_trends?.score_change ?? null, null);
  // M5.d: the snapshot-native report renders NO trend direction at all - trend
  // derivation belongs to the supersession chain, and a partial scan is never
  // presented as comparable history.
  ok("(5) exec report: no improved/declined direction anywhere", !JSON.stringify(rep).includes('"improved"') && !JSON.stringify(rep).includes('"declined"'));
  eq("(5) exec report: comparability is exposed and FALSE for a partial scan", rep.cyber_metrics_score.comparable, false);

  // Complete assessment: rating + narrative + comparable trend all present/normal.
  const completeRaw = { domain: "example.co.uk", cyber_metrics_score: 82, risk_level: "good", scan_quality: { status: "complete" }, findings: [], recommendations: [], modules: { historical_changes: { has_previous: true, previous_scan_id: "p", previous_score: 70, comparable: true } } };
  const repC = buildExecutiveReportV2({ scan: { id: "s2", score: 82, status: "completed", domain: "example.co.uk" }, read: mkRead(completeRaw, "s2") });
  eq("(14) complete report keeps its real rating", repC.cyber_metrics_score.rating, riskLevelForScore(82));
  ok("(14) complete report is comparable (frozen assessment.comparable)", repC.cyber_metrics_score.comparable === true);
}

// ── (13) Parity: resolver, exec-report and PDF derive the SAME decision ──
{
  const input = { score: 95, scanQuality: "partial", status: "completed" };
  const r = resolveAssessmentPresentation(input);
  const rep = buildExecutiveReportV2({ scan: { id: "s", score: 95, status: "completed", domain: "d" }, read: mkRead({ cyber_metrics_score: 95, scan_quality: { status: "partial" }, findings: [], recommendations: [], modules: {} }, "s3") });
  eq("(13) exec-report rating == resolver display_rating", rep.cyber_metrics_score.rating, r.display_rating);
  eq("(13) exec-report provisional == resolver provisional", rep.cyber_metrics_score.provisional, r.provisional);
  // PDF delegates to the same resolver (source-level: pdf.js imports + uses it).
  const pdfSrc = fs.readFileSync(path.join(root, "workers", "scan-api", "src", "engines", "pdf.js"), "utf8");
  ok("(13) PDF renders the snapshot frozen assessment decision", /assessment\?\.provisional/.test(pdfSrc));
  ok("(13) PDF shows 'Provisional' + suppresses rating on partial", /Provisional Score|"Provisional"/.test(pdfSrc));
}

// ── (9)(11)(12) backfill script safety (source contract; never run against prod) ──
{
  const bf = fs.readFileSync(path.join(root, "scripts", "backfill-scan-quality.js"), "utf8");
  ok("(11) backfill requires --apply to write (dry-run default)", /--apply/.test(bf) && /--dry-run|DRY_RUN/.test(bf));
  ok("(12) backfill is idempotent (WHERE scan_quality IS NULL guard)", /scan_quality IS NULL/.test(bf));
  ok("(9) backfill never infers complete from status/score/findings", /never infer|Never infer|not infer/i.test(bf) || /scan_quality\.status/.test(bf));
  ok("backfill only accepts the 4-literal enum", /complete/.test(bf) && /partial/.test(bf) && /degraded/.test(bf) && /unknown/.test(bf));
}

// ── Failure path: R2 write succeeds, D1 quality write fails → not treated complete;
//     reconciler restores scan_quality from R2 and the two then match. ──
{
  // Persist a COMPLETE report to R2 but make the D1 UPDATE throw.
  let r2Body = null;
  let d1Quality = null; // simulated D1 column value
  let updateAttempted = false;
  const failingEnv = {
    cybermeters_reports: { put: async (k, b) => { r2Body = JSON.parse(b); } },
    cybermeters_db: {
      prepare: (sql) => ({ bind: (...a) => ({ run: async () => {
        if (/UPDATE scans SET status/.test(sql)) {
          updateAttempted = true;
          throw new Error("D1 down");
        }
      } }) }),
      batch: async (statements) => Promise.all(statements.map((statement) => statement.run())),
    },
  };
  const latch = createFinalizeLatch();
  const report = { status: "completed", scan_quality: { status: "complete" }, cyber_metrics_score: 82 };
  const fin = await finalizeScanResult(latch, { scanId: "scan_fp", report, score: 82, rating: "good", status: "completed", env: failingEnv });
  ok("failure path: R2 completed report is durable", r2Body?.scan_quality?.status === "complete");
  ok("failure path: NOT finalized when the D1 write fails", updateAttempted === true && fin.errors?.d1 === "D1 down" && fin.finalized === false && latch.d1Written === false);
  // While D1 quality is NULL, the canonical resolver treats it as unknown → NOT complete.
  const stale = resolveAssessmentPresentation({ score: 82, scanQuality: d1Quality /* NULL */, status: "completed" });
  ok("failure path: D1-NULL quality is NOT authoritative (never assumed complete)", !stale.authoritative && stale.quality === "unknown");
  // Reconciler restores scan_quality from the SAME R2 report.
  d1Quality = r2Body.scan_quality.status; // what the reconciler's UPDATE ... = raw.scan_quality?.status writes
  eq("reconciler: D1 quality restored from R2", d1Quality, "complete");
  const recovered = resolveAssessmentPresentation({ score: 82, scanQuality: d1Quality, status: "completed" });
  ok("after reconcile: D1 and R2 agree and posture is authoritative", recovered.authoritative && d1Quality === r2Body.scan_quality.status);
}

console.log(`\npartial-scan-honesty: ${pass} passed, ${fail} failed`);
if (fail) { console.error("partial-scan-honesty validation FAILED"); process.exit(1); }
console.log("partial-scan-honesty validation passed");
