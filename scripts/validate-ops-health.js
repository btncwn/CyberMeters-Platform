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
db.prepare(`INSERT INTO operational_events (id, event_type, correlation_id, status, attempts)
            VALUES ('ops-scheduled-ok', 'scheduled_scan_query', 'scheduled-scan:2026-10-16T08:00', 'ok', 1)`).run();
const realD1 = { prepare: (sql) => ({
  first: async () => db.prepare(sql).get() ?? null,
  bind: (...args) => ({ first: async () => db.prepare(sql).get(...args) ?? null }),
}) };
const realHealth = await computeOpsHealth({ cybermeters_db: realD1 });
ok("real empty schema: healthy", realHealth.healthy === true);
ok("real empty schema: db reachable", realHealth.dbReachable === true);
ok("real empty schema: every signal ran (none skipped)", realHealth.signals.every((s) => !s.skipped));
ok("real empty schema: every signal count is 0", realHealth.signals.every((s) => s.count === 0));
ok("real empty schema: no alert email", formatOpsHealthEmail(realHealth) === null);

// ── 2. Controlled counts via a mock D1 keyed by table name ───────────────────
function mockEnv(counts, { throwAll = false } = {}) {
  const pick = (sql) => {
    if (/scheduled_scan_query/i.test(sql)) return counts.scheduled_scan_query ?? 0;
    if (/FROM scans/i.test(sql)) return counts.stuck_scans ?? 0;
    if (/COALESCE\(error/i.test(sql)) return counts.lifecycle_emails_outcome_unknown ?? 0;
    if (/lifecycle_email_events/i.test(sql)) return counts.failed_lifecycle_emails ?? 0;
    if (/asset_alert_records/i.test(sql)) return counts.failed_asset_alerts ?? 0;
    if (/request_type = 'account'/i.test(sql)) return counts.pending_account_deletions ?? 0;
    if (/status LIKE 'blocked_%'/i.test(sql)) return counts.blocked_deletions ?? 0;
    if (/deletion_requests/i.test(sql)) return counts.overdue_deletions ?? 0;
    return 0;
  };
  return { cybermeters_db: { prepare: (sql) => ({ first: async () => {
    if (throwAll) throw new Error("d1 down");
    return { c: pick(sql) };
  }, bind: () => ({ first: async () => {
    if (throwAll) throw new Error("d1 down");
    return { status: counts.scheduled_scan_query ? "error" : "ok" };
  } }) }) } };
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

// ── 3. Exact A1r outcome-unknown population and exclusions ───────────────────
const insertLifecycle = (id, type, status, error, age) => db.prepare(
  `INSERT INTO lifecycle_email_events (id,type,dedupe_key,status,error,created_at)
   VALUES (?,?,?,?,?,datetime('now',?))`
).run(id, type, `dedupe:${id}`, status, error, age);

insertLifecycle("unknown_sending", "lifecycle_welcome", "sending", "timeout", "-16 minutes");
insertLifecycle("unknown_pending", "lifecycle_welcome", "pending", null, "-16 minutes");
insertLifecycle("unknown_timeout", "lifecycle_welcome", "failed", "timeout", "-16 minutes");
insertLifecycle("unknown_network", "lifecycle_welcome", "failed", "network_error", "-16 minutes");
insertLifecycle("fresh_sending", "lifecycle_welcome", "sending", "timeout", "-14 minutes");
insertLifecycle("marked_pending", "lifecycle_welcome", "pending", "provider_not_started", "-2 days");
insertLifecycle("already_sent", "lifecycle_welcome", "sent", null, "-2 days");
insertLifecycle("safe_preflight", "lifecycle_welcome", "failed", "missing_api_key", "-2 days");
insertLifecycle("safe_rejection", "lifecycle_welcome", "failed", "provider_rejected", "-2 days");
insertLifecycle("payment_unknown", "lifecycle_payment_failed", "sending", "timeout", "-2 days");
insertLifecycle("digest_unknown", "lifecycle_weekly_digest", "pending", null, "-2 days");

const unknownHealth = await computeOpsHealth({ cybermeters_db: realD1 });
const unknownSignal = unknownHealth.signals.find((signal) => signal.key === "lifecycle_emails_outcome_unknown");
ok("outcome unknown: exact stale unknown population counted", unknownSignal?.count === 4);
ok("outcome unknown: threshold 1 breaches", unknownSignal?.threshold === 1 && unknownSignal?.breached === true);
ok("outcome unknown: aggregate unhealthy", unknownHealth.healthy === false);
const unknownMail = formatOpsHealthEmail(unknownHealth, { version: "test" });
ok("outcome unknown: alert email names reconciliation signal", unknownMail?.text.includes("Lifecycle email outcomes requiring reconciliation"));

// The new safety query is fail-closed independently: a read failure stays
// `skipped`, makes the aggregate unhealthy and is named in the email.
const partialDown = {
  cybermeters_db: {
    prepare: (sql) => ({ first: async () => {
      if (/COALESCE\(error/i.test(sql)) throw new Error("outcome query unavailable");
      return { c: 0 };
    }, bind: () => ({ first: async () => ({ status: "ok" }) }) }),
  },
};
const unknownUnreadable = await computeOpsHealth(partialDown);
const unreadableSignal = unknownUnreadable.signals.find((signal) => signal.key === "lifecycle_emails_outcome_unknown");
ok("outcome unknown: query failure remains skipped", unreadableSignal?.skipped === true && unreadableSignal?.count === null);
ok("outcome unknown: query failure fails aggregate closed", unknownUnreadable.dbReachable === true && unknownUnreadable.healthy === false);
ok("outcome unknown: query failure is visible in email", formatOpsHealthEmail(unknownUnreadable)?.text.includes("query unavailable"));

// Account requests and blocked purges must be visible immediately to the next
// heartbeat; the latter cannot silently sit outside the old overdue predicate.
db.prepare("INSERT INTO users(id,email) VALUES ('ops-deletion-user','ops-deletion@example.test')").run();
db.prepare("INSERT INTO deletion_requests(id,request_type,user_id,requested_by,status) VALUES ('ops-pending','account','ops-deletion-user','ops-deletion-user','pending')").run();
db.prepare("INSERT INTO deletion_requests(id,request_type,user_id,requested_by,status) VALUES ('ops-blocked','workspace','ops-deletion-user','ops-deletion-user','blocked_residual_data')").run();
const deletionHealth = await computeOpsHealth({ cybermeters_db: realD1 });
ok("new account request is an operator health breach",
   deletionHealth.signals.find((s) => s.key === "pending_account_deletions")?.count === 1 &&
   deletionHealth.signals.find((s) => s.key === "pending_account_deletions")?.breached === true);
ok("blocked purge is an operator health breach",
   deletionHealth.signals.find((s) => s.key === "blocked_deletions")?.count === 1 &&
   deletionHealth.signals.find((s) => s.key === "blocked_deletions")?.breached === true);
const deletionMail = formatOpsHealthEmail(deletionHealth, { version: "test" });
ok("operator email names both deletion conditions",
   deletionMail?.text.includes("Account deletion requests pending processing") &&
   deletionMail?.text.includes("Deletion requests blocked from completion"));

// An unreadable deletion signal must not turn a genuinely unknown state into
// a reassuring healthy result. The email must identify the failed query.
for (const [key, marker, label] of [
  ["pending_account_deletions", "request_type = 'account'", "Account deletion requests pending processing"],
  ["blocked_deletions", "status LIKE 'blocked_%'", "Deletion requests blocked from completion"],
]) {
  for (const mode of ["throw", "invalid_count"]) {
    const env = {
      cybermeters_db: {
        prepare: (sql) => ({ first: async () => {
          if (sql.includes(marker)) {
            if (mode === "throw") throw new Error("deletion query unavailable");
            return { c: "not-a-number" };
          }
          return { c: 0 };
        } }),
      },
    };
    const health = await computeOpsHealth(env);
    const signal = health.signals.find((s) => s.key === key);
    ok(`${key} ${mode}: signal skipped`, signal?.skipped === true && signal?.count === null);
    ok(`${key} ${mode}: aggregate fails closed`, health.dbReachable === true && health.healthy === false);
    ok(`${key} ${mode}: operator email names unreadable query`,
       formatOpsHealthEmail(health)?.text.includes(`${label}: query unavailable`));
  }
}

// ── 4. Database unreachable → every query skipped → unhealthy + DB alarm ─────
const down = await computeOpsHealth(mockEnv({}, { throwAll: true }));
ok("db down: unhealthy", down.healthy === false);
ok("db down: dbReachable false", down.dbReachable === false);
ok("db down: all signals skipped", down.signals.every((s) => s.skipped));
const downMail = formatOpsHealthEmail(down, { version: "test" });
ok("db down: email warns DB unreachable", downMail !== null && /UNREACHABLE/i.test(downMail.text));

console.log(`\nOps health: ${pass}/${pass + fail} passed`);
if (fail) { console.error("ops-health validation FAILED"); process.exit(1); }
console.log("ops-health validation passed");
