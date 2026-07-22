#!/usr/bin/env node
// validate-scheduled-queue-dispatch.js
//
// PR-B1A (22 Jul 2026 scan-lifecycle sequence): proves the flag-gated migration
// of SCHEDULED scans onto the durable Queue dispatch lifecycle — the REAL
// triggerScheduledScan producer (queued admission → single schedule stamp →
// scheduled_scan_triggered audit → the shared dispatchAdmittedScan boundary),
// the consumer's advisory-trigger threading and scheduled settlement hook, and
// the config pins — all while SCHEDULED_DISPATCH_MODE is OFF in production and
// the legacy direct-engine cron path stays byte-identical.
//
// Layers:
//   A. Module contracts — separate flag fail-safe, scheduled message fields,
//      manual-message byte parity.
//   B. Producer REAL-PATH behaviour — drives the actual triggerScheduledScan
//      (test-only export from index.js) against a real SQLite database
//      (schema + all migrations incl. the REAL 099 index), a recording R2
//      stub and a recording SCAN_QUEUE stub, in BOTH modes. The engine's own
//      first write is parked forever (waitUntil-mode fixture) so the real
//      scan engine never reaches network phases here.
//   C. Consumer settlement — processScanDispatchMessage with an injected
//      engine stub and the REAL settleScheduledQueueScan against the same
//      real database: advisory cross-check, asset counts, failure
//      notification, exactly-once, non-fatal.
//   D. Recovery integration — a stale queued scheduled admission terminalises
//      honestly via the REAL recoverInterruptedScans.
//   E. Static/config contracts — SCHEDULED_DISPATCH_MODE pinned OFF (PR-B1A),
//      SCAN_DISPATCH_MODE untouched, settlement wired in the queue handler,
//      queue branch never invokes the engine from cron, cron/migration
//      invariants (no migration 100).
//
// Mutation directions (reverting the guard reddens the named assertion):
//   - flag helper accepts a non-exact value            → A1 fails
//   - queue-mode INSERT writes 'running' not 'queued'  → B2 fails
//   - scheduled producer hardcodes trigger "manual"    → B2 message fails
//   - scheduled_scan_id dropped from the message       → B2 message fails
//   - engine invoked from cron in queue mode           → B2 park-count fails
//   - stamp moved before admission / duplicated        → B3 (conflict stamps) /
//                                                        B2 stamp-count fails
//   - stamp rolled back after dispatch failure         → B4 fails
//   - stamp-failure compensation removed               → B6 fails
//   - settlement authorises from the message           → C4 fails
//   - settlement notifies without engineError          → C2 fails
//   - settlement fires for manual trigger              → C5 fails
//   - hook failure poisons the ack decision            → C8 fails
//   - recovery loses the queued class                  → D1 fails
//   - wrangler flag flipped ON / removed               → E1 fails
//   - queue-handler settlement injection dropped       → E3 fails
//
// Node 24+ (node:sqlite). No network.

import fs from "node:fs";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const srcPath = (...p) => path.join(root, "workers", "scan-api", "src", ...p);

const {
  isScheduledQueueDispatchMode,
  buildScanDispatchMessage,
  processScanDispatchMessage,
  SCAN_DISPATCH_MESSAGE_VERSION,
} = await import(pathToFileURL(srcPath("engines", "scan-dispatch.js")).href);
const { recoverInterruptedScans } = await import(pathToFileURL(srcPath("engines", "scan-recovery.js")).href);
const { triggerScheduledScan, settleScheduledQueueScan } = await import(pathToFileURL(srcPath("index.js")).href);

let passed = 0, failed = 0;
function ok(name, cond, detail = "") {
  if (cond) { passed++; console.log(`PASS ${name}`); }
  else      { failed++; console.log(`FAIL ${name}${detail ? " — " + detail : ""}`); }
}

// ── Layer A: module contracts ────────────────────────────────────────────────
ok("A1 scheduled flag: only the exact string 'queue' enables dispatch (fail-safe)",
  isScheduledQueueDispatchMode({ SCHEDULED_DISPATCH_MODE: "queue" }) === true &&
  isScheduledQueueDispatchMode({ SCHEDULED_DISPATCH_MODE: "waituntil" }) === false &&
  isScheduledQueueDispatchMode({ SCHEDULED_DISPATCH_MODE: "QUEUE" }) === false &&
  isScheduledQueueDispatchMode({ SCHEDULED_DISPATCH_MODE: "" }) === false &&
  isScheduledQueueDispatchMode({ SCAN_DISPATCH_MODE: "queue" }) === false &&
  isScheduledQueueDispatchMode({}) === false &&
  isScheduledQueueDispatchMode(undefined) === false);

{
  const m = buildScanDispatchMessage({
    scanId: "scan_s1", workspaceId: "ws_s", domainId: "dom_s",
    domain: "sched.example", userId: "user_s",
    trigger: "scheduled", scheduledScanId: "sched_s1",
  });
  ok("A2 scheduled message: v1, trigger scheduled, advisory scheduled_scan_id",
    m.v === SCAN_DISPATCH_MESSAGE_VERSION && m.v === 1 &&
    m.scan_id === "scan_s1" && m.trigger === "scheduled" &&
    m.scheduled_scan_id === "sched_s1");
  const bogus = buildScanDispatchMessage({ scanId: "scan_s2", trigger: "cron-ish" });
  ok("A3 unrecognised trigger fails safe to manual; no scheduled_scan_id key",
    bogus.trigger === "manual" && !("scheduled_scan_id" in bogus));
}

// ── Shared real-database fixture ─────────────────────────────────────────────
const sdb = new DatabaseSync(":memory:", { enableForeignKeyConstraints: false });
{
  const migDir = path.join(root, "database", "migrations");
  const apply = (p) => {
    try { sdb.exec(fs.readFileSync(p, "utf8")); }
    catch (e) { if (!/duplicate|already exists|no such (table|column)/i.test(e.message)) throw e; }
  };
  apply(path.join(root, "database", "schema.sql"));
  for (const f of fs.readdirSync(migDir).filter((x) => x.endsWith(".sql")).sort()) apply(path.join(migDir, f));
}

const FUTURE_ISO = new Date(Date.now() + 365 * 24 * 3600 * 1000).toISOString();
const PAST_ISO   = new Date(Date.now() - 3600 * 1000).toISOString();
sdb.exec(`
  INSERT INTO workspaces (id, name, owner_user_id) VALUES ('ws_S1', 'WS S1', 'user_S1');
  INSERT INTO workspaces (id, name, owner_user_id) VALUES ('ws_S2', 'WS S2', 'user_S2');
  INSERT INTO subscriptions (id, owner_user_id, plan, status, subscription_status, current_period_end)
    VALUES ('sub_S_1', 'user_S1', 'business', 'active', 'active', '${FUTURE_ISO}');
  INSERT INTO subscriptions (id, owner_user_id, plan, status, subscription_status, current_period_end)
    VALUES ('sub_S_2', 'user_S2', 'business', 'active', 'active', '${FUTURE_ISO}');
`);
// Domains: [user, domain, id, verified?]
const DOMS = [
  ["user_S1", "sched-a.co.uk",  "dom_S_a", true],
  ["user_S1", "sched-b.co.uk",  "dom_S_b", true],
  ["user_S1", "sched-e.co.uk",  "dom_S_e", true],
  ["user_S1", "sched-f.co.uk",  "dom_S_f", true],
  ["user_S1", "sched-g.co.uk",  "dom_S_g", true],
  ["user_S1", "sched-h.co.uk",  "dom_S_h", true],
  ["user_S1", "sched-i.co.uk",  "dom_S_i", true],
  ["user_S1", "shared.co.uk",   "dom_S_c1", true],
  ["user_S2", "shared.co.uk",   "dom_S_c2", true],
  ["user_S1", "sched-uv.co.uk", "dom_S_uv", false],
];
for (const [u, d, id, verified] of DOMS) {
  sdb.prepare("INSERT INTO domains (id, user_id, domain) VALUES (?, ?, ?)").run(id, u, d);
  const ws = u === "user_S1" ? "ws_S1" : "ws_S2";
  sdb.prepare("INSERT INTO workspace_domains (workspace_id, domain_id, verification_status) VALUES (?, ?, ?)")
    .run(ws, id, verified ? "verified" : "pending");
}
const mkSchedule = (id, domain, ws = "ws_S1") => {
  sdb.prepare(
    `INSERT INTO scheduled_scans (id, domain, frequency, enabled, next_run_at, workspace_id, created_at)
     VALUES (?, ?, 'daily', 1, ?, ?, ?)`
  ).run(id, domain, PAST_ISO, ws, PAST_ISO);
  return { id, domain, frequency: "daily", workspace_id: ws };
};

const sState = {
  r2Puts: [], r2Poison: null,
  sends: [], sendPoison: null,
  stampPoison: null, stampCount: 0,
  engineParks: 0,
};
function sD1Adapter(sqlite) {
  const poke = (sql) => {
    if (/UPDATE scheduled_scans SET last_run_at/.test(sql)) {
      if (sState.stampPoison) throw sState.stampPoison;
      sState.stampCount++;
    }
  };
  const exec = (sql, args) => ({
    async first() { const r = sqlite.prepare(sql).get(...args); return r === undefined ? null : r; },
    async all()   { return { results: sqlite.prepare(sql).all(...args) }; },
    async run()   {
      // Park the ENGINE's own first write forever (legacy-mode fixture) so the
      // real scan engine never proceeds to network phases in this harness.
      if (/^UPDATE scans SET status = 'running' WHERE id = \?$/.test(sql.trim())) {
        sState.engineParks++;
        return new Promise(() => {});
      }
      poke(sql);
      const info = sqlite.prepare(sql).run(...args);
      return { meta: { changes: Number(info.changes) } };
    },
  });
  return { prepare(sql) { const noArgs = exec(sql, []); return { ...noArgs, bind(...args) { return exec(sql, args); } }; } };
}
function makeScheduledEnv(mode) {
  return {
    cybermeters_db: sD1Adapter(sdb),
    cybermeters_reports: {
      put: async (k, body) => {
        if (sState.r2Poison) throw sState.r2Poison;
        sState.r2Puts.push({ key: k, body: JSON.parse(body) });
      },
      get: async () => null,
    },
    SCAN_QUEUE: {
      send: async (m) => {
        sState.sends.push(m);
        if (sState.sendPoison) throw sState.sendPoison;
      },
    },
    ...(mode ? { SCHEDULED_DISPATCH_MODE: mode } : {}),
  };
}
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
async function waitFor(cond, timeoutMs = 3000) {
  const start = Date.now();
  while (!cond()) {
    if (Date.now() - start > timeoutMs) return false;
    await sleep(5);
  }
  return true;
}
const audits = () => Object.fromEntries(
  sdb.prepare("SELECT event_type, COUNT(*) c FROM audit_events GROUP BY event_type").all().map((r) => [r.event_type, r.c]));
const scanRowFor = (domain, ws = "ws_S1") => sdb.prepare(
  "SELECT id, status, scan_quality, workspace_id, domain_id, domain FROM scans WHERE workspace_id=? AND domain=? ORDER BY created_at DESC LIMIT 1").get(ws, domain);
const schedRowOf = (id) => sdb.prepare("SELECT * FROM scheduled_scans WHERE id=?").get(id);

// ── Layer B: producer real-path behaviour ────────────────────────────────────

// B1 — flag OFF: the legacy direct-engine path is byte-identical (running row,
// running placeholder wording, stamp advanced, triggered audit, engine reached,
// NO Queue traffic). The engine's first write parks, freezing the legacy path
// at its exact pre-network position.
{
  const sched = mkSchedule("sch_off", "sched-a.co.uk");
  triggerScheduledScan(sched, makeScheduledEnv("waituntil")); // deliberately not awaited — parks at the engine
  const reached = await waitFor(() => sState.engineParks === 1);
  const row = scanRowFor("sched-a.co.uk");
  const a = audits();
  const put = sState.r2Puts[sState.r2Puts.length - 1];
  ok("B1 flag OFF: legacy path byte-identical (running row, engine reached, no Queue)",
    reached && row?.status === "running" &&
    put?.body?.status === "running" && /Scheduled scan in progress/.test(put?.body?.message || "") &&
    schedRowOf("sch_off")?.last_run_at !== null &&
    sState.stampCount === 1 &&
    (a.scheduled_scan_triggered || 0) === 1 && (a.scan_started || 0) === 0 &&
    sState.sends.length === 0,
    `reached=${reached} row=${JSON.stringify(row)} audits=${JSON.stringify(a)} sends=${sState.sends.length}`);
}

// B2 — flag ON: queued admission → single stamp → triggered audit → dispatch
// through the ONE boundary; the engine is NEVER invoked from the cron
// invocation; the message carries the scheduled advisory fields.
{
  const sched = mkSchedule("sch_q1", "sched-b.co.uk");
  const before = audits();
  const parksBefore = sState.engineParks;
  const stampsBefore = sState.stampCount;
  await triggerScheduledScan(sched, makeScheduledEnv("queue"));
  const row = scanRowFor("sched-b.co.uk");
  const a = audits();
  const put = sState.r2Puts[sState.r2Puts.length - 1];
  const msg = sState.sends[sState.sends.length - 1];
  ok("B2 queue admission → row status 'queued' (never 'running')",
    row?.status === "queued", JSON.stringify(row));
  ok("B2b queued R2 placeholder: canonical queued copy, scan_quality null",
    put?.body?.status === "queued" && put.body.scan_quality === null &&
    /queued/i.test(put.body.message || "") && put.key === `reports/${row?.id}.json`);
  ok("B2c exactly one v1 message: trigger scheduled + advisory scheduled_scan_id",
    sState.sends.length === 1 && msg?.v === 1 && msg.scan_id === row?.id &&
    msg.trigger === "scheduled" && msg.scheduled_scan_id === "sch_q1" &&
    msg.workspace_id === "ws_S1" && msg.domain === "sched-b.co.uk");
  ok("B2d schedule stamped exactly once; triggered audit exactly once; no scan_started",
    sState.stampCount === stampsBefore + 1 &&
    schedRowOf("sch_q1")?.last_run_at !== null &&
    (a.scheduled_scan_triggered || 0) === (before.scheduled_scan_triggered || 0) + 1 &&
    (a.scan_started || 0) === (before.scan_started || 0));
  ok("B2e engine never invoked from the cron invocation in queue mode",
    sState.engineParks === parksBefore);
}

// B3 — active-scan conflict (the queued row from B2 is still active): the
// second schedule for the same (workspace, domain) skips with ZERO side
// effects and stays due for the next tick.
{
  const sched = mkSchedule("sch_q2", "sched-b.co.uk");
  const scansBefore = sdb.prepare("SELECT COUNT(*) c FROM scans").get().c;
  const sendsBefore = sState.sends.length;
  const stampsBefore = sState.stampCount;
  const auditsBefore = audits();
  await triggerScheduledScan(sched, makeScheduledEnv("queue"));
  ok("B3 conflict with an active scan → skip: no row, no stamp, no audit, no send; stays due",
    sdb.prepare("SELECT COUNT(*) c FROM scans").get().c === scansBefore &&
    sState.sends.length === sendsBefore &&
    sState.stampCount === stampsBefore &&
    schedRowOf("sch_q2")?.last_run_at === null &&
    JSON.stringify(audits()) === JSON.stringify(auditsBefore));
}

// B4 — Queue.send failure → the shared compensation boundary owns the truth:
// row failed (quality NULL), failed R2 report, one scan_dispatch_failed audit,
// and the schedule deliberately STAYS advanced (never rolled back).
{
  const sched = mkSchedule("sch_q3", "sched-e.co.uk");
  sState.sendPoison = new Error("queue down");
  await triggerScheduledScan(sched, makeScheduledEnv("queue"));
  sState.sendPoison = null;
  const row = scanRowFor("sched-e.co.uk");
  const put = sState.r2Puts[sState.r2Puts.length - 1];
  ok("B4 send failure → compensation: failed row (quality NULL), failed report, audit; stamp NOT rolled back",
    row?.status === "failed" && row.scan_quality === null &&
    put?.body?.status === "failed" && put.body.reason === "dispatch_failed" &&
    (audits().scan_dispatch_failed || 0) === 1 &&
    schedRowOf("sch_q3")?.last_run_at !== null,
    JSON.stringify({ row, put: put?.body?.status }));
}

// B5 — R2 placeholder failure → same boundary, stage r2_placeholder: row
// failed honestly; nothing was sent.
{
  const sched = mkSchedule("sch_q4", "sched-f.co.uk");
  const sendsBefore = sState.sends.length;
  sState.r2Poison = new Error("r2 down");
  await triggerScheduledScan(sched, makeScheduledEnv("queue"));
  sState.r2Poison = null;
  const row = scanRowFor("sched-f.co.uk");
  ok("B5 R2 failure → compensation: failed row (quality NULL), no send",
    row?.status === "failed" && row.scan_quality === null &&
    sState.sends.length === sendsBefore);
}

// B6 — schedule-stamp failure (founder decision): the admitted queued scan is
// CAS-failed immediately (quality NULL) and NEVER dispatched — no R2
// placeholder, no send, no triggered audit.
{
  const sched = mkSchedule("sch_q5", "sched-g.co.uk");
  const sendsBefore = sState.sends.length;
  const putsBefore = sState.r2Puts.length;
  const auditsBefore = audits();
  sState.stampPoison = new Error("stamp write failed");
  await triggerScheduledScan(sched, makeScheduledEnv("queue"));
  sState.stampPoison = null;
  const row = scanRowFor("sched-g.co.uk");
  ok("B6 stamp failure → CAS queued→failed (quality NULL), no dispatch, no audit",
    row?.status === "failed" && row.scan_quality === null &&
    sState.sends.length === sendsBefore && sState.r2Puts.length === putsBefore &&
    (audits().scheduled_scan_triggered || 0) === (auditsBefore.scheduled_scan_triggered || 0) &&
    schedRowOf("sch_q5")?.last_run_at === null);
}

// B7 — cross-workspace same domain: 099 is per-(workspace, domain), so both
// workspaces' schedules admit and dispatch independently.
{
  const s1 = mkSchedule("sch_x1", "shared.co.uk", "ws_S1");
  const s2 = mkSchedule("sch_x2", "shared.co.uk", "ws_S2");
  const sendsBefore = sState.sends.length;
  await triggerScheduledScan(s1, makeScheduledEnv("queue"));
  await triggerScheduledScan(s2, makeScheduledEnv("queue"));
  ok("B7 cross-workspace same domain: both admit queued, two dispatches",
    scanRowFor("shared.co.uk", "ws_S1")?.status === "queued" &&
    scanRowFor("shared.co.uk", "ws_S2")?.status === "queued" &&
    sState.sends.length === sendsBefore + 2);
}

// B8 — eligibility failure (unverified domain link): zero side effects.
{
  const sched = mkSchedule("sch_uv", "sched-uv.co.uk");
  const scansBefore = sdb.prepare("SELECT COUNT(*) c FROM scans").get().c;
  const sendsBefore = sState.sends.length;
  const stampsBefore = sState.stampCount;
  await triggerScheduledScan(sched, makeScheduledEnv("queue"));
  ok("B8 eligibility failure → zero side effects (no row, no send, no stamp)",
    sdb.prepare("SELECT COUNT(*) c FROM scans").get().c === scansBefore &&
    sState.sends.length === sendsBefore && sState.stampCount === stampsBefore &&
    schedRowOf("sch_uv")?.last_run_at === null);
}

// ── Layer C: consumer settlement (REAL settleScheduledQueueScan) ─────────────
// A fresh queued scheduled admission (sch_h) provides the real message.
const schedH = mkSchedule("sch_h", "sched-h.co.uk");
await triggerScheduledScan(schedH, makeScheduledEnv("queue"));
const H_MSG = sState.sends[sState.sends.length - 1];
const H_ROW = scanRowFor("sched-h.co.uk");

function makeConsumerDeps({ engineOutcome = "completed", engineThrows = false } = {}) {
  const rec = { engineCalls: [], hookCalls: [], auditCalls: [] };
  const deps = {
    runScanEngine: async (scanId, domainId, workspaceId, domain, env, opts) => {
      rec.engineCalls.push({ scanId, opts });
      // Simulate the canonical latch: the engine self-finalises a terminal row.
      sdb.prepare("UPDATE scans SET status = ?, scan_quality = ? WHERE id = ?")
        .run(engineOutcome, engineOutcome === "completed" ? "complete" : null, scanId);
      if (engineThrows) throw new Error("engine defensive throw");
    },
    heartbeatScan: async () => {},
    createAuditEvent: async (env, evt) => { rec.auditCalls.push(evt); },
    onScheduledScanSettled: async (env, args) => {
      rec.hookCalls.push(args);
      return settleScheduledQueueScan(env, args);
    },
  };
  return { deps, rec };
}
const consumerEnv = makeScheduledEnv("queue");

// C1/C2 — claim → engine with { executionContext queue, trigger scheduled } →
// settlement updates asset counts from D1; completed run notifies NOTHING.
{
  // Seed derived evidence for the settlement's asset-count read.
  const seedAe = sdb.prepare(
    "INSERT INTO asset_events (id, workspace_id, domain_id, scan_id, event_type, created_at) VALUES (?,?,?,?,?,datetime('now'))");
  seedAe.run("ae_1", "ws_S1", "dom_S_h", H_ROW.id, "new_asset_discovered");
  seedAe.run("ae_2", "ws_S1", "dom_S_h", H_ROW.id, "asset_reappeared");
  seedAe.run("ae_3", "ws_S1", "dom_S_h", H_ROW.id, "asset_disappeared");
  const seedWa = sdb.prepare(
    "INSERT INTO workspace_assets (id, workspace_id, domain_id, hostname, asset_type, first_seen, last_seen, status, created_at, updated_at) VALUES (?,?,?,?,'subdomain',datetime('now'),datetime('now'),?,datetime('now'),datetime('now'))");
  seedWa.run("wa_1", "ws_S1", "dom_S_h", "a.sched-h.co.uk", "active");
  seedWa.run("wa_2", "ws_S1", "dom_S_h", "b.sched-h.co.uk", "active");
  seedWa.run("wa_3", "ws_S1", "dom_S_h", "c.sched-h.co.uk", "inactive");

  const { deps, rec } = makeConsumerDeps({ engineOutcome: "completed" });
  const d = await processScanDispatchMessage(H_MSG, consumerEnv, deps);
  const sr = schedRowOf("sch_h");
  const notifs = sdb.prepare("SELECT COUNT(*) c FROM notification_events WHERE type='scheduled_scan_failed'").get().c;
  ok("C1 claim → engine invoked with executionContext queue + trigger scheduled",
    d.action === "ack" && d.outcome === "executed" &&
    rec.engineCalls.length === 1 &&
    rec.engineCalls[0].opts?.executionContext === "queue" &&
    rec.engineCalls[0].opts?.trigger === "scheduled");
  ok("C2 settlement: asset counts derived from D1 (2 changes, 2 active); completed → NO notification",
    rec.hookCalls.length === 1 &&
    sr?.last_asset_count === 2 && sr?.asset_change_count === 2 &&
    notifs === 0,
    JSON.stringify({ sr: { la: sr?.last_asset_count, ac: sr?.asset_change_count }, notifs }));
}

// C3 — engine failure (throw + honest failed row) → exactly one
// scheduled_scan_failed notification, attributed to the workspace owner.
const schedI = mkSchedule("sch_i", "sched-i.co.uk");
await triggerScheduledScan(schedI, makeScheduledEnv("queue"));
const I_MSG = sState.sends[sState.sends.length - 1];
{
  const { deps, rec } = makeConsumerDeps({ engineOutcome: "failed", engineThrows: true });
  const d = await processScanDispatchMessage(I_MSG, consumerEnv, deps);
  const notif = sdb.prepare("SELECT * FROM notification_events WHERE type='scheduled_scan_failed'").all();
  ok("C3 engine failure → engine_error ack + exactly one owner-attributed notification",
    d.outcome === "engine_error" && rec.hookCalls.length === 1 &&
    notif.length === 1 && notif[0].workspace_id === "ws_S1" &&
    notif[0].user_id === "user_S1" && notif[0].severity === "high",
    JSON.stringify(notif.map((n) => ({ ws: n.workspace_id, u: n.user_id }))));
}

// C4 — advisory mismatch: a scheduled_scan_id belonging to ANOTHER workspace
// never settles (no counts write, no notification) — correlation can never
// reattribute across tenants.
{
  const foreign = { ...I_MSG, scan_id: H_ROW.id, scheduled_scan_id: "sch_x2" }; // sch_x2 belongs to ws_S2
  // Reset the H scan to queued so the claim can be won again in isolation.
  sdb.prepare("UPDATE scans SET status='queued' WHERE id=?").run(H_ROW.id);
  const before = schedRowOf("sch_x2");
  const notifsBefore = sdb.prepare("SELECT COUNT(*) c FROM notification_events WHERE type='scheduled_scan_failed'").get().c;
  const { deps } = makeConsumerDeps({ engineOutcome: "failed", engineThrows: true });
  await processScanDispatchMessage(foreign, consumerEnv, deps);
  const after = schedRowOf("sch_x2");
  ok("C4 cross-tenant scheduled_scan_id → settlement silently skips (no write, no notification)",
    after?.last_asset_count === before?.last_asset_count &&
    after?.asset_change_count === before?.asset_change_count &&
    sdb.prepare("SELECT COUNT(*) c FROM notification_events WHERE type='scheduled_scan_failed'").get().c === notifsBefore);
}

// C5 — manual trigger: the settlement hook is NEVER called.
{
  sdb.prepare("UPDATE scans SET status='queued' WHERE id=?").run(H_ROW.id);
  const manual = { ...H_MSG, trigger: "manual" };
  delete manual.scheduled_scan_id;
  const { deps, rec } = makeConsumerDeps();
  const d = await processScanDispatchMessage(manual, consumerEnv, deps);
  ok("C5 manual trigger → executed, hook never called",
    d.outcome === "executed" && rec.hookCalls.length === 0 &&
    rec.engineCalls[0].opts?.trigger === "manual");
}

// C6 — duplicate delivery: claim lost → no engine, no settlement.
{
  const { deps, rec } = makeConsumerDeps();
  const d = await processScanDispatchMessage(H_MSG, consumerEnv, deps); // H row now terminal/running from C5 run
  ok("C6 duplicate delivery → no second engine run, no second settlement",
    (d.outcome === "claim_lost" || d.outcome === "terminal_noop") &&
    rec.engineCalls.length === 0 && rec.hookCalls.length === 0);
}

// C7 — terminal redelivery: no-op before the hook stage.
{
  sdb.prepare("UPDATE scans SET status='completed' WHERE id=?").run(H_ROW.id);
  const { deps, rec } = makeConsumerDeps();
  const d = await processScanDispatchMessage(H_MSG, consumerEnv, deps);
  ok("C7 terminal redelivery → terminal_noop, hook never called",
    d.outcome === "terminal_noop" && rec.hookCalls.length === 0);
}

// C8 — a throwing hook never poisons the ack decision.
{
  sdb.prepare("UPDATE scans SET status='queued' WHERE id=?").run(H_ROW.id);
  const { deps, rec } = makeConsumerDeps();
  deps.onScheduledScanSettled = async () => { throw new Error("hook exploded"); };
  const d = await processScanDispatchMessage(H_MSG, consumerEnv, deps);
  ok("C8 hook failure is non-fatal: decision stays executed/ack",
    d.action === "ack" && d.outcome === "executed" && rec.engineCalls.length === 1);
}

// ── Layer D: recovery integration ────────────────────────────────────────────
// D1 — a stale queued scheduled admission (lost message / dead-lettered)
// terminalises honestly via the REAL recovery: failed, quality NULL,
// status_before 'queued' in the append-only evidence.
{
  sdb.prepare(
    `INSERT INTO scans (id, domain_id, workspace_id, domain, status, created_at)
     VALUES ('scan_stale_q', 'dom_S_a', 'ws_S1', 'stale-sched.co.uk', 'queued', ?)`
  ).run(new Date(Date.now() - 2 * 3600 * 1000).toISOString());
  const env = makeScheduledEnv();
  const summary = await recoverInterruptedScans(env, { now: Date.now() });
  const row = sdb.prepare("SELECT status, scan_quality FROM scans WHERE id='scan_stale_q'").get();
  const evt = sdb.prepare(
    "SELECT metadata_json FROM audit_events WHERE event_type='scan_interrupted_recovered' AND entity_id='scan_stale_q'").all();
  ok("D1 stale queued scheduled scan → recovery terminalises failed (quality NULL, status_before queued)",
    row?.status === "failed" && row.scan_quality === null &&
    summary.recovered_interrupted >= 1 &&
    evt.length === 1 && /"status_before":"queued"/.test(evt[0].metadata_json || ""),
    JSON.stringify({ row, summary }));
}

// ── Layer E: static/config contracts ─────────────────────────────────────────
const wranglerSrc = fs.readFileSync(path.join(root, "workers", "scan-api", "wrangler.toml"), "utf8");
const stripToml = wranglerSrc.replace(/#[^\n]*/g, "").replace(/\r/g, "");
const indexSrc = fs.readFileSync(srcPath("index.js"), "utf8");

// E1 — PR-B1A ships INERT: the scheduled flag is present and pinned OFF. The
// PR-B1B cutover must flip this assertion in the SAME commit as the config
// (the E2d lockstep pattern), keeping the deployed mode and its pin together.
ok("E1 SCHEDULED_DISPATCH_MODE present and pinned OFF (\"waituntil\") for PR-B1A",
  /^SCHEDULED_DISPATCH_MODE = "waituntil"$/m.test(stripToml));

// E2 — the LIVE manual flag is untouched by this PR.
ok("E2 SCAN_DISPATCH_MODE remains \"queue\" (manual path untouched)",
  /^SCAN_DISPATCH_MODE = "queue"$/m.test(stripToml));

// E3 — the queue handler wires the settlement hook (dropping the injection
// silently disables scheduled settlement in production).
ok("E3 queue handler injects onScheduledScanSettled: settleScheduledQueueScan",
  /queue: \(batch, env, ctx\) => handleScanDispatchBatch\(batch, env, ctx, \{ onScheduledScanSettled: settleScheduledQueueScan \}\)/.test(indexSrc));

// E4 — inside triggerScheduledScan, the queue branch returns via dispatch and
// never reaches the direct engine call (behavioural twin: B2e).
{
  const start = indexSrc.indexOf("async function triggerScheduledScan");
  const end = indexSrc.indexOf("async function settleScheduledQueueScan");
  const slice = indexSrc.slice(start, end > start ? end : undefined);
  const dispatchIdx = slice.indexOf('trigger: "scheduled"');
  const engineIdx = slice.indexOf('executionContext: "cron"');
  ok("E4 queue branch (scheduled dispatch) precedes the legacy direct-engine call",
    start > -1 && dispatchIdx > -1 && engineIdx > dispatchIdx);
}

// E5 — cron registration and migration surface unchanged: hourly cron, and NO
// migration 100 exists (PR-B1 is code-only by founder decision).
ok("E5 hourly cron unchanged", /crons = \["0 \* \* \* \*"\]/.test(wranglerSrc));
ok("E5b no migration 100 exists",
  !fs.readdirSync(path.join(root, "database", "migrations")).some((f) => /^100-/.test(f)));

console.log(`\nscheduled-queue-dispatch: ${passed} passed, ${failed} failed`);
if (failed) { console.error("scheduled-queue-dispatch validation FAILED"); process.exit(1); }
console.log("scheduled-queue-dispatch validation passed");
