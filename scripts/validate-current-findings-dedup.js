#!/usr/bin/env node
//
// Current-findings de-duplication — behavioural proof of the ONE canonical
// latest-COMPLETE-scan-per-domain scope (report-queries.js LATEST_COMPLETED_SCAN_SCOPE)
// that the Executive Dashboard, Workspace Insights, executive report and PDF all
// share. It runs the real exported scope SQL against a seeded node:sqlite DB and
// proves a finding repeated across several scans of a domain is counted ONCE, that
// a partial/degraded/unknown latest scan never fabricates or replaces authoritative
// current findings, and that created_at ties resolve deterministically by id DESC.
// Node 24+. CI-blocking.
import path from "node:path";
import { DatabaseSync } from "node:sqlite";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const { LATEST_COMPLETED_SCAN_SCOPE } = await import(
  pathToFileURL(path.join(root, "workers", "scan-api", "src", "engines", "report-queries.js")).href
);

let pass = 0, fail = 0;
const ok = (n, c, d = "") => { c ? pass++ : fail++; if (!c) console.log(`FAIL ${n}${d ? " — " + d : ""}`); };

const db = new DatabaseSync(":memory:");
db.exec(`
  CREATE TABLE workspace_domains (workspace_id TEXT, domain_id TEXT);
  CREATE TABLE scans (id TEXT PRIMARY KEY, domain_id TEXT, domain TEXT, status TEXT, score INTEGER, scan_quality TEXT, created_at TEXT, workspace_id TEXT);
  CREATE TABLE findings (id TEXT PRIMARY KEY, scan_id TEXT, severity TEXT, title TEXT);
`);
const W = "ws1", WB = "ws_other";
const A = "domA", B = "domB", X = "domX";
db.exec(`INSERT INTO workspace_domains VALUES ('${W}','${A}'),('${W}','${B}'),('${WB}','${X}');`);

let fc = 0;
const scan = (id, dom, domainStr, status, quality, created, ws = W) =>
  db.prepare(`INSERT INTO scans VALUES (?,?,?,?,?,?,?,?)`).run(id, dom, domainStr, status, 80, quality, created, ws);
const finding = (scanId, sev, title) =>
  db.prepare(`INSERT INTO findings VALUES (?,?,?,?)`).run(`f${fc++}`, scanId, sev, title);

// Domain A — THREE complete scans, each with the SAME critical finding (the pile-up
// the dashboard used to triple-count) + a resolved finding only on the oldest scan.
scan("a1", A, "a.com", "completed", "complete", "2026-07-10 10:00:00");
finding("a1", "critical", "HTTPS Not Available");
finding("a1", "high", "Old Issue Since Resolved");
scan("a2", A, "a.com", "completed", "complete", "2026-07-12 10:00:00");
finding("a2", "critical", "HTTPS Not Available");
scan("a3", A, "a.com", "completed", "complete", "2026-07-14 10:00:00"); // LATEST complete
finding("a3", "critical", "HTTPS Not Available");
finding("a3", "high", "Admin Interface Exposed"); // a second, distinct current finding

// Domain B — its own latest-complete scan with the SAME critical title as A (must
// count independently per domain, not merge).
scan("b1", B, "b.com", "completed", "complete", "2026-07-14 09:00:00");
finding("b1", "critical", "HTTPS Not Available");

// Foreign workspace — must never leak into W's counts.
scan("x1", X, "x.com", "completed", "complete", "2026-07-14 12:00:00", WB);
finding("x1", "critical", "SHOULD NOT LEAK");

const countBySeverity = (ws, sev) => db.prepare(
  `SELECT COUNT(f.id) AS n FROM findings f
   JOIN scans s ON s.id = f.scan_id
   JOIN workspace_domains wd ON wd.domain_id = s.domain_id
   WHERE wd.workspace_id = ? AND f.severity = ? AND ${LATEST_COMPLETED_SCAN_SCOPE}`
).get(ws, sev, ws).n;

const titlesFor = (ws) => db.prepare(
  `SELECT f.title FROM findings f
   JOIN scans s ON s.id = f.scan_id
   JOIN workspace_domains wd ON wd.domain_id = s.domain_id
   WHERE wd.workspace_id = ? AND ${LATEST_COMPLETED_SCAN_SCOPE}`
).all(ws, ws).map((r) => r.title);

// 1. The repeated critical finding across 3 scans of domain A is counted once for A,
//    plus once for domain B (same title, different domain) = 2 total critical.
ok("repeated finding counted once per domain (A=1) + independent domain B (=1) => 2 critical",
  countBySeverity(W, "critical") === 2, `got ${countBySeverity(W, "critical")}`);

// 2. Two DIFFERENT current findings on A's latest scan are counted separately.
ok("distinct current findings counted separately (high on A's latest = 1)",
  countBySeverity(W, "high") === 1, `got ${countBySeverity(W, "high")}`);

// 3. A finding present only on an OLDER scan (resolved by the latest) is not counted.
ok("resolved finding from an older scan is not counted",
  !titlesFor(W).includes("Old Issue Since Resolved"));

// 4. Domain boundary — the foreign workspace's finding never appears.
ok("no cross-workspace leakage", !titlesFor(W).includes("SHOULD NOT LEAK") && countBySeverity(WB, "critical") === 1);

// 5. created_at TIE resolves deterministically by id DESC (exactly one scan wins).
//    Same timestamp; id "btie2" > "btie1" lexically, so ORDER BY id DESC picks btie2.
scan("btie1", B, "b.com", "completed", "complete", "2026-07-15 09:00:00");
finding("btie1", "critical", "Tie Loser");
scan("btie2", B, "b.com", "completed", "complete", "2026-07-15 09:00:00");
finding("btie2", "critical", "Tie Winner");
{
  const t = titlesFor(W);
  const bothTied = t.includes("Tie Loser") && t.includes("Tie Winner");
  ok("created_at tie resolves deterministically by id DESC (exactly one tied scan wins, no double-count)",
    !bothTied && t.includes("Tie Winner"));
}

// 6. A newer PARTIAL scan must NOT replace or fabricate authoritative current findings:
//    domain A gets a newer partial scan with a bogus finding — it must be ignored,
//    and A's authoritative critical finding (from the latest COMPLETE scan) remains.
scan("a4_partial", A, "a.com", "completed", "partial", "2026-07-16 10:00:00");
finding("a4_partial", "critical", "PARTIAL SHOULD NOT SHOW");
{
  const t = titlesFor(W);
  ok("newer partial scan does not fabricate a current finding", !t.includes("PARTIAL SHOULD NOT SHOW"));
  ok("newer partial scan does not remove the authoritative complete finding", t.includes("HTTPS Not Available"));
  // critical count unchanged: A(1) + B(1 tie winner) = 2 (partial ignored).
  ok("partial latest does not change the authoritative critical count",
    countBySeverity(W, "critical") === 2, `got ${countBySeverity(W, "critical")}`);
}

// 7. A domain whose ONLY latest scan is degraded/unknown contributes no current findings.
scan("c_degraded", "domC", "c.com", "completed", "degraded", "2026-07-16 11:00:00");
db.exec(`INSERT INTO workspace_domains VALUES ('${W}','domC');`);
finding("c_degraded", "critical", "DEGRADED ONLY");
ok("degraded-only domain contributes no authoritative current findings",
  !titlesFor(W).includes("DEGRADED ONLY"));

console.log(`\ncurrent-findings-dedup: ${pass} passed, ${fail} failed`);
if (fail) { console.error("current-findings-dedup validation FAILED"); process.exit(1); }
console.log("current-findings-dedup validation passed");
