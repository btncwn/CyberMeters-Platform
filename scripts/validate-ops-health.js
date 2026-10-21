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
import { spawnSync } from "node:child_process";

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

// The daily founder email, the silent-rejection counter and the feedback /
// browser-error intake belong to the same ops lane; their tests run here.
{
  const { spawnSync } = await import("node:child_process");
  const repo = new URL("..", import.meta.url).pathname;
  const run = spawnSync(process.execPath, ["--test", "workers/scan-api/test/ops-observability.test.js"],
    { cwd: repo, stdio: "inherit", timeout: 180000 });
  ok("ops observability: counters, intake, founder daily email and retention tests", run.status === 0);
}

// C-8 weekly off-site success/freshness and safe operator-email proof.
{
  const { randomBytes } = await import('node:crypto');
  const { encodeBackup, verifyBackup, weeklyApi, digest } = await import('./ops/weekly-backup.mjs');
  const { open } = await import('./ops/cloudflare-recovery.mjs');
  const { gunzipSync } = await import('node:zlib');
  const { weeklyBackupHealth, WEEKLY_BACKUP_MAX_AGE_MINUTES } = await import('../workers/scan-api/src/lib/weekly-backup-health.js');
  const key = randomBytes(32);
  const sql = 'CREATE TABLE recovery_fixture(id INTEGER PRIMARY KEY); INSERT INTO recovery_fixture VALUES (1);';
  const data = { schema: 1, database: 'fd6792cb-441a-44a7-8ca2-9a0b411ec706', bucket: 'cybermeters-reports', run: '123-1', captured_at: '2026-10-21T12:00:00Z', sql, objects: [{ key: 'private-fixture', size: 4, etag: 'fixture' }] };
  const bytes = encodeBackup(data, key);
  const receipt = { run: data.run, bytes: bytes.length, sha256: digest(bytes) };
  ok('weekly encrypted package decrypts and exercises SQL integrity', verifyBackup(bytes, key, receipt).objects === 1);
  ok('weekly ciphertext contains neither SQL nor object names', !bytes.includes(Buffer.from('recovery_fixture')) && !bytes.includes(Buffer.from('private-fixture')));
  const throws = fn => { try { fn(); return false; } catch { return true; } };
  ok('weekly wrong key rejected', throws(() => verifyBackup(bytes, randomBytes(32), receipt)));
  ok('weekly readback corruption rejected', throws(() => verifyBackup(Buffer.concat([bytes, Buffer.from('x')]), key, receipt)));
  ok('weekly foreign run receipt rejected', throws(() => verifyBackup(bytes, key, { ...receipt, run: '999-1' })));
  ok('weekly foreign database rejected before encrypt', throws(() => encodeBackup({ ...data, database: 'foreign' }, key)));
  const broken = encodeBackup({ ...data, sql: 'not valid sql' }, key);
  ok('weekly invalid SQL never verifies', throws(() => verifyBackup(broken, key, { ...receipt, bytes: broken.length, sha256: digest(broken) })));
  const calls = [];
  let drift = false, lists = 0;
  const fakeFetch = async (url, options = {}) => {
    const path = new URL(url).pathname;
    calls.push({ path, options });
    if (path === '/export.sql') {
      ok('weekly signed export receives no account token', !options.headers?.Authorization);
      return new Response(sql);
    }
    if (path.endsWith('/objects/private-fixture')) {
      return new Response('fixture bytes', { headers: { 'x-amz-meta-fixture': 'retained', 'cache-control': 'private, max-age=60' } });
    }
    let result;
    if (path.endsWith('/objects')) { lists++; result = drift && lists % 2 === 0 ? [] : data.objects; }
    else if (path.endsWith('/export')) result = { status: 'complete', result: { signed_url: 'https://fixture.r2.cloudflarestorage.com/export.sql' } };
    else if (path.endsWith('/query')) {
      const request = JSON.parse(options.body);
      result = request.sql.startsWith('SELECT') ? [{ results: [{ created_at: '2026-10-21 12:00:00' }] }] : [];
    } else throw Error('Unexpected fixture path');
    return Response.json({ success: true, result });
  };
  const client = weeklyApi('fixture-token', fakeFetch);
  data.objects[0].storage_class = 'InfrequentAccess';
  let paidClassRejected = false;
  try { await client.capture('122-1', key); } catch { paidClassRejected = true; }
  ok('weekly capture rejects a retrieval-priced storage class before object GETs',
    paidClassRejected && !calls.some(call => call.path.endsWith('/objects/private-fixture')));
  delete data.objects[0].storage_class;
  const captured = await client.capture('123-1', key);
  const capturedManifest = JSON.parse(gunzipSync(open(captured.bytes, key)));
  ok('weekly encrypted manifest retains observed HTTP and custom metadata',
    capturedManifest.objects[0].response_headers['x-amz-meta-fixture'] === 'retained' &&
    capturedManifest.objects[0].response_headers['cache-control'] === 'private, max-age=60');
  ok('weekly capture cannot record freshness before off-site upload', !calls.some(call => call.path.endsWith('/query')));
  const priorCalls = calls.length;
  try { await client.record(captured.receipt, Buffer.from('corrupt'), key); } catch { /* expected */ }
  ok('weekly failed off-site readback makes no event API call', calls.length === priorCalls);
  const recorded = await client.record(captured.receipt, captured.bytes, key);
  ok('weekly success records and reads back a real event timestamp', recorded.last_success_at === '2026-10-21 12:00:00' && calls.filter(call => call.path.endsWith('/query')).length === 2);
  drift = true; lists = 0;
  let driftFailed = false;
  try { await client.capture('124-1', key); } catch { driftFailed = true; }
  ok('weekly source inventory drift rejects capture', driftFailed);
  const row = { event_type: 'weekly_backup_completed', correlation_id: 'github-weekly:123-1', status: 'ok', created_at: '2026-10-21 12:00:00' };
  const fixtureEnv = value => ({ cybermeters_db: { prepare: () => ({ bind: () => ({ first: async () => value }) }) } });
  const nowMs = Date.parse('2026-10-21T12:00:00Z');
  ok('weekly freshness uses last actual success', (await weeklyBackupHealth(fixtureEnv(row), { nowMs })).last_success_at === '2026-10-21T12:00:00.000Z');
  ok('weekly eight-day boundary remains fresh', (await weeklyBackupHealth(fixtureEnv(row), { nowMs: nowMs + WEEKLY_BACKUP_MAX_AGE_MINUTES * 60000 })).fresh);
  ok('weekly older than eight days is stale', !(await weeklyBackupHealth(fixtureEnv(row), { nowMs: nowMs + (WEEKLY_BACKUP_MAX_AGE_MINUTES + 1) * 60000 })).fresh);
  for (const [label, value] of [['absent', null], ['manual', { ...row, correlation_id: 'cloudflare:manual' }], ['failed', { ...row, status: 'failed' }], ['bad-date', { ...row, created_at: 'bad' }], ['future', { ...row, created_at: '2026-10-22T12:00:00Z' }]]) {
    ok(`weekly ${label} evidence fails closed`, !(await weeklyBackupHealth(fixtureEnv(value), { nowMs })).fresh);
  }
  const weeklyEnv = { cybermeters_db: realD1, WEEKLY_BACKUP_MONITORING: 'on', INDEPENDENT_BACKUP_MONITORING: 'off' };
  const missing = await computeOpsHealth(weeklyEnv);
  const mail = formatOpsHealthEmail(missing);
  ok('weekly missing proof creates an operator-email alert', !missing.healthy && mail?.text.includes('Weekly off-site backup missing'));
  const { computeOperationalHealth } = await import('../workers/scan-api/src/lib/ops-health.js');
  const missingReady = await computeOperationalHealth(weeklyEnv, { nowMs });
  ok('weekly readiness cannot inherit manual exemption', missingReady.backup_fresh === false && missingReady.backup_required === true && missingReady.backup_last_success_at === null);
  const weeklyDown = await computeOpsHealth({ ...mockEnv({}, { throwAll: true }), WEEKLY_BACKUP_MONITORING: 'on' });
  ok('weekly missing proof preserves database-unreachable reporting', weeklyDown.dbReachable === false && !weeklyDown.healthy);
  db.prepare("INSERT INTO operational_events(id,event_type,correlation_id,status,attempts,created_at) VALUES ('weekly-fixture','weekly_backup_completed','github-weekly:123-1','ok',1,?)").run(new Date().toISOString());
  const healthy = await computeOpsHealth(weeklyEnv);
  ok('weekly fresh proof does not generate a backup email', healthy.signals.find(s => s.key === 'weekly_backup_stale')?.breached === false && !(formatOpsHealthEmail(healthy)?.text || '').includes('Weekly off-site backup missing'));
  const ready = await computeOperationalHealth(weeklyEnv);
  ok('weekly readiness carries real success time and cadence', ready.backup_fresh === true && ready.backup_cadence === 'weekly' && typeof ready.backup_last_success_at === 'string');
  const workflow = fs.readFileSync(path.join(root, '.github/workflows/weekly-backup.yml'), 'utf8');
  const order = ['Capture and encrypt', 'Store encrypted copy', 'Download the durable', 'Verify off-site readback'].map(name => workflow.indexOf(name));
  ok('weekly workflow records only after upload and download', order.every((index, n) => index >= 0 && (n === 0 || index > order[n-1])));
  ok('weekly workflow has bounded free allocation and explicit founder enable', workflow.includes('retention-days: 21') && workflow.includes('timeout-minutes: 10') && workflow.includes("vars.WEEKLY_BACKUP_ENABLED == 'true'"));
  ok('weekly workflow refuses public artifact destinations before any steps', /^    if: github\.event\.repository\.private == true && /m.test(workflow));
  const sourceGate = workflow.match(/^        run: '(\[\[.*\]\])'$/m)?.[1];
  for (const [ref, expected] of [['a'.repeat(40), 0], ['main', 1], ['', 1], ['$(echo unsafe)', 1]]) {
    const result = sourceGate ? spawnSync('bash', ['-c', sourceGate], { env: { ...process.env, BACKUP_SOURCE_REF: ref } }) : {};
    ok(`weekly source pin gate ${ref === 'main' ? 'rejects mutable main' : expected === 0 ? 'accepts reviewed SHA' : ref ? 'rejects shell-shaped value' : 'rejects missing SHA'}`, result.status === expected);
  }
  ok('weekly workflow checks out only the pinned public implementation', workflow.includes('repository: btncwn/CyberMeters-Platform') && workflow.includes('ref: ${{ vars.BACKUP_SOURCE_REF }}'));
  ok('weekly workflow uploads only encrypted bytes', workflow.includes('/captured/weekly-backup.bin') && !workflow.includes('path: ${{ runner.temp }}/captured\n'));
}

console.log(`\nOps health: ${pass}/${pass + fail} passed`);
if (fail) { console.error("ops-health validation FAILED"); process.exit(1); }
console.log("ops-health validation passed");
