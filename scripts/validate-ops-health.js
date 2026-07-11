#!/usr/bin/env node
//
// Ops-health monitoring regression: the daily heartbeat must (1) run its
// signal queries cleanly against the REAL schema, (2) stay silent when healthy,
// (3) fire on each threshold breach, and (4) detect an unreachable database —
// without ever false-alarming on a healthy system. Guards the monitoring that
// catches silent-accumulation failures (stuck scans, undelivered-email backlog,
// overdue purges). Requires Node 24+ (node:sqlite). CI-blocking.
//
import fs from "node:fs";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const { computeOpsHealth, formatOpsHealthEmail, OPS_THRESHOLDS } = await import(
  pathToFileURL(path.join(root, "workers", "scan-api", "src", "lib", "ops-health.js")).href
);

let pass = 0, fail = 0;
const ok = (name, cond) => { cond ? pass++ : fail++; if (!cond) console.log("FAIL " + name); };

// ── 1. Real schema: an empty but valid DB must be healthy (proves the signal
//      SQL references real tables/columns and runs clean). ────────────────────
const db = new DatabaseSync(":memory:");
const apply = (p) => { try { db.exec(fs.readFileSync(p, "utf8")); } catch { /* ordering/dup no-ops */ } };
apply(path.join(root, "database", "schema.sql"));
for (const f of fs.readdirSync(path.join(root, "database", "migrations")).filter((f) => f.endsWith(".sql")).sort()) {
  apply(path.join(root, "database", "migrations", f));
}
const realD1 = { prepare: (sql) => ({ first: async () => db.prepare(sql).get() ?? null }) };
const realHealth = await computeOpsHealth({ cybermeters_db: realD1 });
ok("real empty schema: healthy", realHealth.healthy === true);
ok("real empty schema: db reachable", realHealth.dbReachable === true);
ok("real empty schema: every signal ran (none skipped)", realHealth.signals.every((s) => !s.skipped));
ok("real empty schema: every signal count is 0", realHealth.signals.every((s) => s.count === 0));
ok("real empty schema: no alert email", formatOpsHealthEmail(realHealth) === null);

// ── 2. Controlled counts via a mock D1 keyed by table name ───────────────────
function mockEnv(counts, { throwAll = false } = {}) {
  const pick = (sql) => {
    if (/FROM scans/i.test(sql)) return counts.stuck_scans;
    if (/lifecycle_email_events/i.test(sql)) return counts.failed_lifecycle_emails;
    if (/asset_alert_records/i.test(sql)) return counts.failed_asset_alerts;
    if (/deletion_requests/i.test(sql)) return counts.overdue_deletions;
    return 0;
  };
  return { cybermeters_db: { prepare: (sql) => ({ first: async () => {
    if (throwAll) throw new Error("d1 down");
    return { c: pick(sql) };
  } }) } };
}

// All well below threshold → healthy, silent.
const calm = await computeOpsHealth(mockEnv({ stuck_scans: 0, failed_lifecycle_emails: 2, failed_asset_alerts: 1, overdue_deletions: 0 }));
ok("calm: healthy", calm.healthy === true);
ok("calm: no email", formatOpsHealthEmail(calm) === null);

// Boundary: exactly threshold-1 does NOT breach; exactly threshold DOES.
const belowStuck = await computeOpsHealth(mockEnv({ stuck_scans: OPS_THRESHOLDS.stuck_scans - 1, failed_lifecycle_emails: 0, failed_asset_alerts: 0, overdue_deletions: 0 }));
ok("boundary: threshold-1 does not breach", belowStuck.healthy === true);
const atStuck = await computeOpsHealth(mockEnv({ stuck_scans: OPS_THRESHOLDS.stuck_scans, failed_lifecycle_emails: 0, failed_asset_alerts: 0, overdue_deletions: 0 }));
ok("boundary: threshold breaches", atStuck.healthy === false);
ok("boundary: correct signal flagged", atStuck.signals.find((s) => s.key === "stuck_scans")?.breached === true);

// Each signal independently trips the alert.
for (const key of Object.keys(OPS_THRESHOLDS)) {
  const counts = { stuck_scans: 0, failed_lifecycle_emails: 0, failed_asset_alerts: 0, overdue_deletions: 0 };
  counts[key] = OPS_THRESHOLDS[key] + 5;
  const h = await computeOpsHealth(mockEnv(counts));
  ok(`signal ${key}: breaches when over threshold`, h.healthy === false && h.signals.find((s) => s.key === key)?.breached === true);
  const mail = formatOpsHealthEmail(h, { version: "test" });
  ok(`signal ${key}: email generated`, mail !== null && typeof mail.subject === "string");
  ok(`signal ${key}: email names the breach`, mail.text.includes(String(counts[key])));
}

// Multiple breaches at once are all reported.
const multi = await computeOpsHealth(mockEnv({ stuck_scans: 9, failed_lifecycle_emails: 40, failed_asset_alerts: 0, overdue_deletions: 3 }));
const multiMail = formatOpsHealthEmail(multi, { version: "test" });
ok("multi: unhealthy", multi.healthy === false);
ok("multi: subject counts breaches", /3 check/.test(multiMail.subject));
ok("multi: healthy asset signal not listed", !multiMail.text.includes("asset-change"));

// ── 3. Database unreachable → every query skipped → unhealthy + DB alarm ─────
const down = await computeOpsHealth(mockEnv({}, { throwAll: true }));
ok("db down: unhealthy", down.healthy === false);
ok("db down: dbReachable false", down.dbReachable === false);
ok("db down: all signals skipped", down.signals.every((s) => s.skipped));
const downMail = formatOpsHealthEmail(down, { version: "test" });
ok("db down: email warns DB unreachable", downMail !== null && /UNREACHABLE/i.test(downMail.text));

console.log(`\nOps health: ${pass}/${pass + fail} passed`);
if (fail) { console.error("ops-health validation FAILED"); process.exit(1); }
console.log("ops-health validation passed");
