#!/usr/bin/env node
//
// DMARC impact forecast + post-change monitor regression.
// Drives the pure impact engine over real in-memory SQLite schema/migrations.
// Proves report-date windowing, pct scaling, legitimate-vs-risky split with
// manual override, insufficient-data honesty, and tenant isolation. Node 24+.
//
import fs from "node:fs";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const impact = await import(pathToFileURL(path.join(root, "workers", "scan-api", "src", "engines", "dmarc-impact.js")).href);
const {
  IMPACT_MIN_MESSAGES,
  ROLLBACK_LEGIT_FAIL_PP,
  assessImpactRollback,
  comparePolicyImpact,
  forecastPolicyImpact,
} = impact;

let pass = 0, fail = 0;
const ok = (name, cond) => { cond ? pass++ : fail++; if (!cond) console.log("FAIL " + name); };

function buildDb() {
  const db = new DatabaseSync(":memory:");
  const apply = (p) => { try { db.exec(fs.readFileSync(p, "utf8")); } catch { /* ordering no-ops */ } };
  apply(path.join(root, "database", "schema.sql"));
  for (const f of fs.readdirSync(path.join(root, "database", "migrations")).filter((f) => f.endsWith(".sql")).sort()) {
    apply(path.join(root, "database", "migrations", f));
  }
  db.exec("PRAGMA foreign_keys = OFF");
  return db;
}

function makeD1(db) {
  const wrap = (sql, args) => ({
    first: async () => db.prepare(sql).get(...args) ?? null,
    all: async () => ({ results: db.prepare(sql).all(...args), success: true, meta: {} }),
    run: async () => { const r = db.prepare(sql).run(...args); return { success: true, meta: { changes: r.changes } }; },
  });
  return { prepare(sql) { const b = wrap(sql, []); b.bind = (...args) => wrap(sql, args); return b; } };
}

const db = buildDb();
const env = { cybermeters_db: makeD1(db) };
const now = new Date("2026-07-13T12:00:00Z");
const nowEpoch = Math.floor(now.getTime() / 1000);
const day = 86400;
let rid = 0, recid = 0;

function seedSender({ ws = "ws_a", domain = "acme.co.uk", ip, auto = "unknown", manual = null, provider = "unknown" }) {
  db.prepare(`INSERT INTO email_sender_sources
    (id, workspace_id, domain, source_ip, provider_guess, classification, classified_at,
     auto_classification, auto_confidence, auto_reasons, total_messages, aligned_messages,
     failed_messages, spf_aligned_messages, dkim_aligned_messages, pass_rate, provider_map_version)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0.8, '[]', 0, 0, 0, 0, 0, 0, 'test')`)
    .run(`sender_${ws}_${ip.replace(/\W/g, "_")}`, ws, domain, ip, provider,
      manual || "unknown", manual ? "2026-07-10T00:00:00Z" : null, auto);
}

function seedRecord({ ws = "ws_a", domain = "acme.co.uk", ip, count, aligned, begin }) {
  const reportId = `rep_${++rid}`;
  db.prepare(`INSERT INTO dmarc_aggregate_reports
    (id, workspace_id, domain, org_name, external_report_id, date_range_begin, date_range_end,
     record_count, message_count, created_at)
    VALUES (?, ?, ?, 'Unit', ?, ?, ?, 1, ?, datetime('now'))`)
    .run(reportId, ws, domain, `ext_${rid}`, begin, begin + 3600, count);
  db.prepare(`INSERT INTO dmarc_aggregate_records
    (id, report_id, workspace_id, domain, source_ip, message_count, dkim_aligned_result,
     spf_aligned_result, header_from, created_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))`)
    .run(`rec_${++recid}`, reportId, ws, domain, ip, count,
      aligned ? "pass" : "fail", aligned ? "pass" : "fail", domain);
}

// Forecast window: 400 total, 100 failed. Of affected mail at pct=50:
// 15 legitimate (authorised + manual trusted) and 35 risky.
seedSender({ ip: "203.0.113.10", auto: "authorised", provider: "microsoft" });
seedSender({ ip: "203.0.113.11", auto: "suspicious", provider: "unknown" });
seedSender({ ip: "203.0.113.12", auto: "suspicious", manual: "trusted", provider: "unknown" });
seedRecord({ ip: "203.0.113.10", count: 100, aligned: true, begin: nowEpoch - day });
seedRecord({ ip: "203.0.113.10", count: 20, aligned: false, begin: nowEpoch - day });
seedRecord({ ip: "203.0.113.11", count: 70, aligned: false, begin: nowEpoch - day });
seedRecord({ ip: "203.0.113.11", count: 200, aligned: true, begin: nowEpoch - day });
seedRecord({ ip: "203.0.113.12", count: 10, aligned: false, begin: nowEpoch - day });

const forecast50 = await forecastPolicyImpact(env, "ws_a", "acme.co.uk", {
  targetPolicy: "reject", targetPct: 50, windowDays: 7, now,
});
ok("forecast total messages", forecast50.total_messages === 400);
ok("forecast pct scaling", forecast50.affected_messages === 50 && forecast50.affected_percentage === 12.5);
ok("forecast legitimate affected includes manual trusted", forecast50.legitimate_affected_messages === 15);
ok("forecast risky affected", forecast50.risky_affected_messages === 35);
ok("forecast sender breakdown includes who gets hurt", forecast50.legitimate_affected_senders.some((s) => s.source_ip === "203.0.113.12" && s.classification === "authorised"));

const forecast100 = await forecastPolicyImpact(env, "ws_a", "acme.co.uk", {
  targetPolicy: "reject", targetPct: 100, windowDays: 7, now,
});
ok("forecast 100 pct doubles affected from 50 pct", forecast100.affected_messages === 100 && forecast100.legitimate_affected_messages === 30);
const forecastNone = await forecastPolicyImpact(env, "ws_a", "acme.co.uk", {
  targetPolicy: "none", targetPct: 100, windowDays: 7, now,
});
ok("forecast none affects no mail", forecastNone.affected_messages === 0);

seedSender({ domain: "thin.co.uk", ip: "198.51.100.1", auto: "authorised" });
seedRecord({ domain: "thin.co.uk", ip: "198.51.100.1", count: IMPACT_MIN_MESSAGES - 1, aligned: false, begin: nowEpoch - day });
const thin = await forecastPolicyImpact(env, "ws_a", "thin.co.uk", { now });
ok("insufficient_data on thin forecast", thin.insufficient_data === true);

// Before/after monitor: legitimate failures increase after change.
seedSender({ domain: "monitor.co.uk", ip: "192.0.2.10", auto: "authorised", provider: "google" });
const changeAt = nowEpoch - 2 * day;
seedRecord({ domain: "monitor.co.uk", ip: "192.0.2.10", count: 100, aligned: true, begin: changeAt - day });
seedRecord({ domain: "monitor.co.uk", ip: "192.0.2.10", count: 100, aligned: false, begin: changeAt + day });
const comparison = await comparePolicyImpact(env, "ws_a", "monitor.co.uk", {
  changeAt, windowDays: 2, now,
});
ok("compare detects legitimate failure increase", comparison.delta.legitimate_failed_rate_increase === 100);
const assessment = assessImpactRollback(comparison);
ok("assessment recommends rollback past threshold", assessment.rollbackRecommended === true && assessment.triggers.length > 0);

// Stable monitor: no false positive when before and after are equally healthy.
seedSender({ domain: "stable.co.uk", ip: "192.0.2.20", auto: "authorised", provider: "google" });
seedRecord({ domain: "stable.co.uk", ip: "192.0.2.20", count: 100, aligned: true, begin: changeAt - day });
seedRecord({ domain: "stable.co.uk", ip: "192.0.2.20", count: 100, aligned: true, begin: changeAt + day });
const stable = await comparePolicyImpact(env, "ws_a", "stable.co.uk", { changeAt, windowDays: 2, now });
ok("stable compare has no legitimate failure increase", stable.delta.legitimate_failed_rate_increase === 0);
ok("stable assessment does not recommend rollback", assessImpactRollback(stable).rollbackRecommended === false);

seedSender({ domain: "unknown-drift.co.uk", ip: "192.0.2.30", auto: "unknown" });
seedRecord({ domain: "unknown-drift.co.uk", ip: "192.0.2.30", count: 50, aligned: true, begin: changeAt - day });
seedRecord({ domain: "unknown-drift.co.uk", ip: "192.0.2.30", count: 80, aligned: true, begin: changeAt + day });
const unknownDrift = await comparePolicyImpact(env, "ws_a", "unknown-drift.co.uk", { changeAt, windowDays: 2, now });
ok("compare reports unknown-volume delta", unknownDrift.delta.unknown_messages_change === 30);

const below = assessImpactRollback({
  before: { insufficient_data: false },
  after: { insufficient_data: false },
  delta: { legitimate_failed_rate_increase: ROLLBACK_LEGIT_FAIL_PP },
});
ok("assessment threshold is strictly greater than configured pp", below.rollbackRecommended === false);

// Tenant isolation: same domain/source in another workspace is not included.
seedSender({ ws: "ws_b", domain: "acme.co.uk", ip: "203.0.113.10", auto: "authorised" });
seedRecord({ ws: "ws_b", domain: "acme.co.uk", ip: "203.0.113.10", count: 1000, aligned: false, begin: nowEpoch - day });
const isolated = await forecastPolicyImpact(env, "ws_a", "acme.co.uk", {
  targetPolicy: "reject", targetPct: 100, windowDays: 7, now,
});
ok("forecast is tenant-isolated", isolated.total_messages === 400 && isolated.affected_messages === 100);

console.log(`\nDMARC impact: ${pass}/${pass + fail} passed`);
if (fail) { console.error("dmarc-impact validation FAILED"); process.exit(1); }
console.log("dmarc-impact validation passed");
