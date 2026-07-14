#!/usr/bin/env node
//
// Executive-report findings/recommendations scoping (customer-trust regression).
//
// The workspace executive report (GET /api/workspaces/:id/report) must show the
// CURRENT posture: each finding / recommendation from the LATEST completed scan per
// domain, exactly once. The pre-fix query had no latest-scan scope, so every
// historical scan's findings piled up — a real BBB report rendered ONE "HTTPS Not
// Available" finding (from 4 old scans) as "CRITICAL (4)" and one "DMARC p=none"
// (from 9 scans) as nine MEDIUM rows, and resurfaced an HTTPS issue already resolved
// by the newest scan. This proves REPORT_FINDINGS_SQL / REPORT_RECOMMENDATIONS_SQL:
//   • scope to the latest COMPLETED scan per domain (resolved issues drop off)
//   • never duplicate a finding across historical scans
//   • cover every domain's latest scan (multi-domain workspaces)
//   • ignore failed/running scans
//   • isolate to the workspace
//   • and a negative control shows the OLD unscoped query DID pile up.
//
// Node 24+ (node:sqlite). CI-blocking.
import path from "node:path";
import { DatabaseSync } from "node:sqlite";
import { fileURLToPath, pathToFileURL } from "node:url";
const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const eng = (f) => import(pathToFileURL(path.join(root, "workers", "scan-api", "src", "engines", f)).href);
const { REPORT_FINDINGS_SQL, REPORT_RECOMMENDATIONS_SQL } = await eng("report-queries.js");

let pass = 0, fail = 0;
const ok = (n, c, d = "") => { c ? pass++ : fail++; if (!c) console.log(`FAIL ${n}${d ? " — " + d : ""}`); };
const eq = (n, g, w) => ok(n, g === w, `got ${JSON.stringify(g)} want ${JSON.stringify(w)}`);

// ── Fixture DB — minimal columns the report queries reference ──
const db = new DatabaseSync(":memory:");
db.exec(`
  CREATE TABLE domains (id TEXT PRIMARY KEY, domain TEXT);
  CREATE TABLE workspace_domains (workspace_id TEXT, domain_id TEXT);
  CREATE TABLE scans (id TEXT PRIMARY KEY, domain_id TEXT, domain TEXT, status TEXT, score INTEGER, created_at TEXT, workspace_id TEXT, scan_quality TEXT);
  CREATE TABLE findings (id TEXT PRIMARY KEY, scan_id TEXT, severity TEXT, title TEXT, recommendation TEXT, created_at TEXT);
  CREATE TABLE remediation_items (id TEXT PRIMARY KEY, scan_id TEXT, priority TEXT, title TEXT, reason TEXT, action TEXT);
`);
const W1 = "ws_bbb", W2 = "ws_other";
const dom1 = "dom_bbb", dom2 = "dom_ex", domX = "dom_x";
db.exec(`
  INSERT INTO domains VALUES ('${dom1}','blackbullbarbers.co.uk'),('${dom2}','example.com'),('${domX}','other.com');
  INSERT INTO workspace_domains VALUES ('${W1}','${dom1}'),('${W1}','${dom2}'),('${W2}','${domX}');
`);
let sc = 0, fi = 0, re = 0;
const scan = (id, domId, dom, status, created, ws = W1, quality = "complete") =>
  db.prepare(`INSERT INTO scans VALUES (?,?,?,?,?,?,?,?)`).run(id, domId, dom, status, 80, created, ws, quality);
const finding = (scanId, sev, title) =>
  db.prepare(`INSERT INTO findings VALUES (?,?,?,?,?,?)`).run(`f${fi++}`, scanId, sev, title, "fix it", "2026-07-14");
const rec = (scanId, prio, title) =>
  db.prepare(`INSERT INTO remediation_items VALUES (?,?,?,?,?,?)`).run(`r${re++}`, scanId, String(prio), title, "reason", "action");

// D1 (BBB): an OLD completed scan with an HTTPS issue (later resolved) + DMARC, and
// FOUR historical scans each repeating HTTPS + DMARC (the pile-up source).
for (let i = 0; i < 4; i++) {
  const sid = `s_bbb_old_${i}`;
  scan(sid, dom1, "blackbullbarbers.co.uk", "completed", `2026-07-13 1${i}:00:00`);
  finding(sid, "critical", "HTTPS Not Available");
  finding(sid, "medium", "DMARC Policy is Monitor-Only (p=none)");
  rec(sid, 1, "Install a TLS Certificate");
  rec(sid, 2, "Strengthen DMARC Policy");
}
// D1 (BBB): the LATEST completed scan — HTTPS resolved; DMARC + admin remain.
const S_LATEST = "s_bbb_latest";
scan(S_LATEST, dom1, "blackbullbarbers.co.uk", "completed", "2026-07-14 01:40:04");
finding(S_LATEST, "medium", "DMARC Policy is Monitor-Only (p=none)");
finding(S_LATEST, "medium", "Administrative Interface Publicly Reachable");
rec(S_LATEST, 2, "Strengthen DMARC Policy");
// D1: a still-newer FAILED scan — must be ignored (no findings, but proves status gate).
scan("s_bbb_failed", dom1, "blackbullbarbers.co.uk", "failed", "2026-07-14 02:00:00");
// D2 (example.com): latest completed scan with one finding — multi-domain coverage.
scan("s_ex_latest", dom2, "example.com", "completed", "2026-07-14 01:00:00");
finding("s_ex_latest", "high", "Expiring TLS Certificate");
rec("s_ex_latest", 1, "Renew certificate");
// W2 (other workspace): its own scan+finding — must never appear in W1's report.
scan("s_other", domX, "other.com", "completed", "2026-07-14 03:00:00", W2);
finding("s_other", "critical", "SHOULD NOT LEAK");
rec("s_other", 1, "SHOULD NOT LEAK REC");

// ── Run the SHIPPING queries (workspace id bound twice) ──
const findings = db.prepare(REPORT_FINDINGS_SQL).all(W1, W1);
const recs     = db.prepare(REPORT_RECOMMENDATIONS_SQL).all(W1, W1);
const titles   = findings.map((r) => r.title);

// ── 1. Resolved issue drops off ──
ok("HTTPS (resolved by latest scan) no longer appears", !titles.includes("HTTPS Not Available"));

// ── 2. No duplication — each latest-scan finding appears exactly once ──
eq("DMARC appears exactly once (was 9x pre-fix)", titles.filter((t) => t === "DMARC Policy is Monitor-Only (p=none)").length, 1);
eq("Admin interface appears exactly once", titles.filter((t) => t === "Administrative Interface Publicly Reachable").length, 1);

// ── 3. Latest scan's real findings are present ──
ok("latest DMARC finding present", titles.includes("DMARC Policy is Monitor-Only (p=none)"));
ok("latest admin finding present", titles.includes("Administrative Interface Publicly Reachable"));

// ── 4. Multi-domain: D2's latest finding is included ──
ok("second domain's latest finding present", titles.includes("Expiring TLS Certificate"));

// ── 5. Workspace isolation ──
ok("other workspace's finding does NOT leak", !titles.includes("SHOULD NOT LEAK"));

// ── 6. Exact expected set: D1(DMARC, admin) + D2(cert) = 3, no criticals, no dupes ──
eq("total report findings = 3 (was 17 in the real BBB report)", findings.length, 3);
eq("no CRITICAL findings (the 4x HTTPS pile-up is gone)", findings.filter((r) => r.severity === "critical").length, 0);

// ── 7. Recommendations scoped + deduped the same way ──
const recTitles = recs.map((r) => r.title);
ok("TLS recommendation (resolved) dropped", !recTitles.includes("Install a TLS Certificate"));
eq("DMARC recommendation appears once (was 6x pre-fix)", recTitles.filter((t) => t === "Strengthen DMARC Policy").length, 1);
ok("second domain recommendation present", recTitles.includes("Renew certificate"));
ok("other workspace recommendation does NOT leak", !recTitles.includes("SHOULD NOT LEAK REC"));

// ── 8. Negative control: the OLD unscoped query DID pile up (proves the fix matters) ──
const OLD_SQL = `SELECT f.title, f.severity FROM findings f
  JOIN scans s ON s.id = f.scan_id
  JOIN domains d ON d.id = s.domain_id
  JOIN workspace_domains wd ON wd.domain_id = d.id
  WHERE wd.workspace_id = ? LIMIT 30`;
const oldTitles = db.prepare(OLD_SQL).all(W1).map((r) => r.title);
ok("negative control: old query piled up HTTPS 4x", oldTitles.filter((t) => t === "HTTPS Not Available").length === 4);
ok("negative control: old query piled up DMARC 5x", oldTitles.filter((t) => t === "DMARC Policy is Monitor-Only (p=none)").length === 5);
ok("fix reduces the pile-up", oldTitles.length > findings.length);

console.log(`\nreport-findings-scoping: ${pass} passed, ${fail} failed`);
if (fail > 0) process.exit(1);
