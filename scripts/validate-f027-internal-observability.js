#!/usr/bin/env node
//
// F-027 internal observability — focused contract validator (Node 24+).
// Exercises the REAL producers/consumers with an in-memory D1 double:
//   • operational-events: idempotency, safe-field rejection, fail-closed persist
//   • scan-dlq-observer: persist-BEFORE-ack, no-ack on failure, never the engine
//   • ops-health: fail-closed freshness/staleness booleans; /ready contract
//   • sendAlertEmail {sent:false} -> durable delivery-failure event (item 3)

import { DatabaseSync } from "node:sqlite";
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const eng = (rel) => pathToFileURL(path.join(root, rel)).href;

let pass = 0, fail = 0;
const ok = (name, cond, detail = "") => { cond ? pass++ : fail++; console.log(`${cond ? "PASS" : "FAIL"} ${name}${cond ? "" : (detail ? " — " + detail : "")}`); };

// ── in-memory D1 double (sync sqlite behind the async .prepare/.bind API) ─────
function makeEnv() {
  const db = new DatabaseSync(":memory:");
  // Apply migration 108 statement-by-statement (mirrors the statement-level
  // instrument: each statement must apply cleanly on its own).
  const mig = fs.readFileSync(path.join(root, "database/migrations/108-operational-events.sql"), "utf8");
  for (const stmt of mig.split(/;\s*(?:\n|$)/).map((x) => x.trim()).filter(Boolean)) db.exec(stmt);
  db.exec(`CREATE TABLE scans (id TEXT PRIMARY KEY, status TEXT, created_at TEXT)`);
  const wrap = (sql, args = []) => ({
    async first() { try { return db.prepare(sql).get(...args) ?? null; } catch { return null; } },
    async all()   { return { results: db.prepare(sql).all(...args) }; },
    async run()   { const r = db.prepare(sql).run(...args); return { success: true, meta: { changes: r.changes } }; },
    bind(...a)    { return wrap(sql, a); },
  });
  return {
    cybermeters_db: { prepare: (sql) => wrap(sql) },
    _db: db,
  };
}

const { persistOperationalEvent, latestOperationalEvent, countRecentOperationalEvents,
        recordAlertDeliveryOutcome, resolveQueueConsumer, OPS_EVENT_TYPES } =
  await import(eng("workers/scan-api/src/lib/operational-events.js"));
const { handleScanDlqBatch } = await import(eng("workers/scan-api/src/queues/scan-dlq-observer.js"));
const { computeOperationalHealth, isOperationallyHealthy, evaluateDeadman } = await import(eng("workers/scan-api/src/lib/ops-health.js"));

// ── operational-events ────────────────────────────────────────────────────────
{
  const env = makeEnv();
  const r1 = await persistOperationalEvent(env, { eventType: "cron_tick", correlationId: "cron:2026-08-26T10", status: "ok" });
  ok("event persists durably", r1.persisted === true, JSON.stringify(r1));
  const r2 = await persistOperationalEvent(env, { eventType: "cron_tick", correlationId: "cron:2026-08-26T10", status: "ok" });
  ok("idempotent: same (type,correlation) is durable again, no duplicate", r2.persisted === true);
  const n = env._db.prepare("SELECT COUNT(*) AS n FROM operational_events").get().n;
  ok("idempotent: exactly ONE row for the duplicate logical event", n === 1, `rows=${n}`);
  ok("deterministic id: duplicate maps to the same primary key", r1.id === r2.id, `${r1.id} vs ${r2.id}`);

  const bad = await persistOperationalEvent(env, { eventType: "cron tick", correlationId: "x", status: "ok" });
  ok("safe-field guard: an unsafe event_type (space) is rejected, not stored", bad.persisted === false && bad.reason === "unsafe_or_missing_field");
  const proseLen = env._db.prepare("SELECT COUNT(*) AS n FROM operational_events").get().n;
  ok("no unsafe row leaked from the rejected write", proseLen === 1);

  const failEnv = { cybermeters_db: { prepare: () => ({ bind: () => ({ async run() { throw new Error("db down"); } }) }) } };
  const rf = await persistOperationalEvent(failEnv, { eventType: "cron_tick", correlationId: "c:1", status: "ok" });
  ok("fail closed: a DB error yields persisted:false (caller must not ack)", rf.persisted === false);
}

// ── scan-dlq-observer: persist BEFORE ack, no-ack on failure, never the engine ─
{
  const env = makeEnv();
  const acks = [], retries = [];
  const msg = (id, scanId) => ({ id, body: { scanId }, ack: () => acks.push(id), retry: () => retries.push(id) });
  const res = await handleScanDlqBatch({ queue: "cybermeters-scan-dlq", messages: [msg("m1", "scan_a"), msg("m2", "scan_b")] }, env);
  ok("DLQ observe: durable event per message", res.observed === 2 && res.deferred === 0, JSON.stringify(res));
  ok("DLQ observe: message ACKED only after persist", acks.length === 2 && retries.length === 0);
  const rows = env._db.prepare("SELECT correlation_id FROM operational_events WHERE event_type='scan_dlq_observed' ORDER BY correlation_id").all();
  ok("DLQ observe: safe correlation ids stored (scan ids)", rows.length === 2 && rows[0].correlation_id === "scan_a");

  // Persist failure -> NO ack, message retried (fail closed).
  const failEnv = { cybermeters_db: { prepare: () => ({ bind: () => ({ async run() { throw new Error("x"); } }) }) } };
  const acks2 = [], retries2 = [];
  const r2 = await handleScanDlqBatch({ queue: "cybermeters-scan-dlq",
    messages: [{ id: "m3", body: { scanId: "scan_c" }, ack: () => acks2.push("m3"), retry: () => retries2.push("m3") }] }, failEnv);
  ok("DLQ fail closed: unpersisted message is NOT acked, it retries", acks2.length === 0 && retries2.length === 1 && r2.deferred === 1);
}

// ── ops-health: fail-closed booleans + /ready extension shape ─────────────────
{
  const env = makeEnv();
  // No cron/backup events, no scans -> cron/backup NOT fresh (fail closed), no stale scan.
  const h0 = await computeOperationalHealth(env);
  ok("freshness fail-closed: absent cron tick -> cron_fresh:false", h0.cron_fresh === false);
  ok("freshness fail-closed: absent backup -> backup_fresh:false", h0.backup_fresh === false);
  ok("not-yet-overall-healthy when signals are unproven", isOperationallyHealthy(h0) === false);

  // Fresh cron + backup, no stuck scan -> healthy.
  await persistOperationalEvent(env, { eventType: "cron_tick", correlationId: "cron:now", status: "ok" });
  await persistOperationalEvent(env, { eventType: "backup_completed", correlationId: "backup:now", status: "ok" });
  const h1 = await computeOperationalHealth(env);
  ok("fresh cron+backup -> cron_fresh and backup_fresh true", h1.cron_fresh === true && h1.backup_fresh === true);
  ok("overall operationally healthy when fresh and no stuck scan", isOperationallyHealthy(h1) === true);

  // A stuck queued scan (created 2h ago) -> stale_queued_scan true -> unhealthy.
  env._db.prepare("INSERT INTO scans (id,status,created_at) VALUES ('s1','queued', strftime('%Y-%m-%dT%H:%M:%fZ','now','-120 minutes'))").run();
  const h2 = await computeOperationalHealth(env);
  ok("stuck queued scan -> stale_queued_scan:true -> not healthy", h2.stale_queued_scan === true && isOperationallyHealthy(h2) === false);

  // Recent DLQ event surfaces but does not by itself flip healthy.
  await persistOperationalEvent(env, { eventType: OPS_EVENT_TYPES.SCAN_DLQ_OBSERVED, correlationId: "scan_x", status: "observed" });
  env._db.prepare("DELETE FROM scans").run();
  const h3 = await computeOperationalHealth(env);
  ok("recent_dlq surfaced as advisory, does not alone flip healthy", h3.recent_dlq === true && isOperationallyHealthy(h3) === true);
}

// ── queue dispatch by identity (contract item 1) ──────────────────────────────
{
  ok("routing: the scan DLQ goes to the observer, never the engine",
    resolveQueueConsumer("cybermeters-scan-dlq") === "dlq_observer");
  ok("routing: the scan-dispatch queue runs the engine",
    resolveQueueConsumer("cybermeters-scan-dispatch") === "scan_dispatch");
  ok("routing: an unknown queue defaults to scan_dispatch, never dlq masquerade",
    resolveQueueConsumer("something-else") === "scan_dispatch");
}

// ── sendAlertEmail {sent:false} -> durable delivery-failure event (item 3) ─────
{
  const env = makeEnv();
  const failOutcome = await recordAlertDeliveryOutcome(env, { sent: false, reason: "feature_not_entitled" }, "ops_health:h1");
  ok("alert outcome: a {sent:false} is recorded as a durable failure event",
    failOutcome.recorded === true && failOutcome.persisted === true, JSON.stringify(failOutcome));
  const row = env._db.prepare("SELECT status FROM operational_events WHERE event_type='alert_delivery_failed'").get();
  ok("alert outcome: the durable event carries the safe reason, no prose", row && row.status === "feature_not_entitled");
  const okOutcome = await recordAlertDeliveryOutcome(env, { sent: true, provider_id: "x" }, "ops_health:h2");
  ok("alert outcome: a confirmed send records NOTHING (no false failure)", okOutcome.recorded === false);
  const cnt = env._db.prepare("SELECT COUNT(*) AS n FROM operational_events WHERE event_type='alert_delivery_failed'").get().n;
  ok("alert outcome: exactly one failure row, none for the success", cnt === 1, `rows=${cnt}`);

  // A delivery REFUSAL and a transport THROW are DIFFERENT events (98's note):
  // the durable record must distinguish them in `status`, not collapse both into
  // one opaque "failed" — ops needs "why", not just "not sent".
  const env2 = makeEnv();
  await recordAlertDeliveryOutcome(env2, { sent: false, reason: "no_verified_recipient" }, "ops_health:r1"); // refusal
  await recordAlertDeliveryOutcome(env2, { sent: false, reason: "sender_threw" }, "ops_health:r2");          // transport throw
  const statuses = env2._db.prepare("SELECT status FROM operational_events WHERE event_type='alert_delivery_failed' ORDER BY status").all().map((r) => r.status);
  ok("alert outcome: refusal and transport-throw are recorded as DISTINCT reasons",
    statuses.includes("no_verified_recipient") && statuses.includes("sender_threw") && statuses.length === 2,
    JSON.stringify(statuses));
}

// ── deadman verdict (contract item 5): 200 alone is NOT healthy ───────────────
{
  const healthyBody = { operational: { cron_fresh: true, backup_fresh: true, stale_queued_scan: false, recent_dlq_readable: true } };
  ok("deadman: 200 + valid JSON + true operational fields -> healthy",
    evaluateDeadman(true, healthyBody).healthy === true);
  ok("deadman: 200 but body did not parse -> NOT healthy",
    evaluateDeadman(true, null).healthy === false);
  ok("deadman: 200 but no operational fields -> NOT healthy",
    evaluateDeadman(true, { status: "ready" }).healthy === false);
  ok("deadman: 200 but cron stale -> NOT healthy",
    evaluateDeadman(true, { operational: { cron_fresh: false, backup_fresh: true, stale_queued_scan: false } }).healthy === false);
  ok("deadman: non-200 -> NOT healthy regardless of body",
    evaluateDeadman(false, healthyBody).healthy === false);
}

// ── R1-02: recent-DLQ READ FAILURE is distinguishable from a proven zero, and
// reads operationally UNHEALTHY (an unmeasured window is never a measured zero) ──
{
  // Proven-empty window: cron+backup fresh, DLQ read SUCCEEDS returning zero.
  const envZero = makeEnv();
  await persistOperationalEvent(envZero, { eventType: "cron_tick", correlationId: "cron:z", status: "ok" });
  await persistOperationalEvent(envZero, { eventType: "backup_completed", correlationId: "backup:z", status: "ok" });
  const hZero = await computeOperationalHealth(envZero);
  ok("R1-02: a PROVEN-zero DLQ window -> events:0, readable:true, operationally healthy",
    hZero.recent_dlq_events === 0 && hZero.recent_dlq_readable === true && isOperationallyHealthy(hZero) === true,
    JSON.stringify({ e: hZero.recent_dlq_events, r: hZero.recent_dlq_readable }));

  // Scoped read failure: cron+backup+stale reads succeed, ONLY the recent-DLQ
  // COUNT read throws. An in-memory .first() swallows, so the throw is injected
  // for exactly that query while every other read delegates to the real double.
  const env = makeEnv();
  await persistOperationalEvent(env, { eventType: "cron_tick", correlationId: "cron:rf", status: "ok" });
  await persistOperationalEvent(env, { eventType: "backup_completed", correlationId: "backup:rf", status: "ok" });
  const realPrepare = env.cybermeters_db.prepare;
  const throwing = { bind() { return this; },
    async first() { throw new Error("dlq read down"); },
    async all() { throw new Error("dlq read down"); },
    async run() { throw new Error("dlq read down"); } };
  env.cybermeters_db = {
    prepare: (sql) => /COUNT\(\*\) AS n FROM operational_events/i.test(sql) ? throwing : realPrepare(sql),
  };
  const hFail = await computeOperationalHealth(env);
  ok("R1-02: a DLQ read FAILURE is DISTINGUISHABLE from zero (events:null, readable:false)",
    hFail.recent_dlq_events === null && hFail.recent_dlq_readable === false,
    JSON.stringify({ e: hFail.recent_dlq_events, r: hFail.recent_dlq_readable }));
  ok("R1-02: cron/backup/stale still measured true — only the DLQ read failed (scoped)",
    hFail.cron_fresh === true && hFail.backup_fresh === true && hFail.stale_queued_scan === false,
    JSON.stringify(hFail));
  ok("R1-02: a DLQ read failure reads operationally UNHEALTHY (fail closed)",
    isOperationallyHealthy(hFail) === false);
  const dm = evaluateDeadman(true, { operational: hFail });
  ok("R1-02: the actual deadman CONSUMES the read-failure truth -> NOT healthy, recent_dlq_unreadable",
    dm.healthy === false && dm.reason === "recent_dlq_unreadable", JSON.stringify(dm));
  // Privacy: only the safe operational booleans/ints are exposed — no correlation
  // ids, raw rows or error prose reach the JSON the deadman consumes.
  const exposedKeys = Object.keys(hFail).sort().join(",");
  ok("R1-02: exposed fields are the safe operational token set only (no prose/correlation)",
    /^backup_age_minutes,backup_fresh,cron_age_minutes,cron_fresh,recent_dlq,recent_dlq_events,recent_dlq_readable,stale_queued_scan$/.test(exposedKeys),
    exposedKeys);
}

// ── R1-01: the ACTUAL workflow decision path (the entrypoint the YAML invokes),
// exercised end-to-end — NOT a disconnected pure-JS twin. jq's `//`/`-r` fragility
// is gone; exact JSON booleans decide, string impostors and missing/invalid fields
// fail closed, and the healthy verdict proves the recovery branch is reachable. ──
{
  const ENTRY = path.join(root, "scripts/ops-deadman-verdict.mjs");
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "f027-entry-"));
  let idx = 0;
  const runEntry = (code, body) => {
    const p = path.join(tmpDir, `ready-${idx++}.json`);
    fs.writeFileSync(p, typeof body === "string" ? body : JSON.stringify(body));
    const out = execFileSync(process.execPath, [ENTRY, String(code), p], { encoding: "utf8" });
    return {
      healthy: /(?:^|\n)healthy=([^\n]*)/.exec(out)?.[1],
      reason: /(?:^|\n)reason=([^\n]*)/.exec(out)?.[1],
    };
  };
  const OP = (o) => ({ operational: { cron_fresh: true, backup_fresh: true, stale_queued_scan: false, recent_dlq_readable: true, ...o } });

  const good = runEntry(200, OP());
  ok("entrypoint(REAL path): correct healthy booleans @200 -> healthy=true reason=ok (RECOVERY branch reachable)",
    good.healthy === "true" && good.reason === "ok", JSON.stringify(good));

  const allStr = runEntry(200, { operational: { cron_fresh: "true", backup_fresh: "true", stale_queued_scan: "false", recent_dlq_readable: "true" } });
  ok("entrypoint: all-string-impostor booleans @200 -> fail closed (healthy=false)",
    allStr.healthy === "false", JSON.stringify(allStr));

  const staleStr = runEntry(200, OP({ stale_queued_scan: "false" }));
  ok("entrypoint: a single string impostor on stale_queued_scan -> fail closed (not the boolean)",
    staleStr.healthy === "false" && staleStr.reason === "stale_queued_scan", JSON.stringify(staleStr));

  const noOp = runEntry(200, { status: "ready" });
  ok("entrypoint: missing operational block @200 -> fail closed (no_operational_fields)",
    noOp.healthy === "false" && noOp.reason === "no_operational_fields", JSON.stringify(noOp));

  const badJson = runEntry(200, "{ not valid json");
  ok("entrypoint: invalid JSON body @200 -> fail closed (invalid_json)",
    badJson.healthy === "false" && badJson.reason === "invalid_json", JSON.stringify(badJson));

  const non200 = runEntry(503, OP());
  ok("entrypoint: a non-200 probe -> fail closed regardless of body (http_503)",
    non200.healthy === "false" && non200.reason === "http_503", JSON.stringify(non200));

  const readFail = runEntry(200, OP({ recent_dlq_readable: false }));
  ok("entrypoint: recent-DLQ read-failure payload @200 -> fail closed (recent_dlq_unreadable)",
    readFail.healthy === "false" && readFail.reason === "recent_dlq_unreadable", JSON.stringify(readFail));

  // ── delta R1: recent_dlq_readable is TYPE-AND-VALUE enforced. Every variant here
  // keeps cron/backup/stale VALID so execution REACHES the recent-DLQ field (the
  // all-string control above dies earlier on cron_fresh and never tests it). Only
  // the literal boolean `true` is healthy; string "true"/"false", null and ABSENCE
  // fail closed, so an older/malformed/schema-drifted body cannot silence the
  // deadman without proving the window readable.
  const opReadable = (rdr, present = true) => {
    const operational = { cron_fresh: true, backup_fresh: true, stale_queued_scan: false };
    if (present) operational.recent_dlq_readable = rdr;
    return { operational };
  };
  const readableCases = [
    ["literal true",  opReadable(true),           "true",  "ok"],
    ["literal false", opReadable(false),          "false", "recent_dlq_unreadable"],
    ["string 'false'", opReadable("false"),       "false", "recent_dlq_unreadable"],
    ["string 'true'",  opReadable("true"),        "false", "recent_dlq_unreadable"],
    ["null",           opReadable(null),          "false", "recent_dlq_unreadable"],
    ["absent",         opReadable(undefined, false), "false", "recent_dlq_unreadable"],
  ];
  for (const [label, body, wantHealthy, wantReason] of readableCases) {
    const r = runEntry(200, body);
    ok(`entrypoint(ISOLATED): recent_dlq_readable ${label} -> healthy=${wantHealthy} reason=${wantReason}`,
      r.healthy === wantHealthy && r.reason === wantReason, JSON.stringify(r));
    // The OTHER consumer must agree, under the same TYPE-AND-VALUE contract.
    ok(`isOperationallyHealthy(ISOLATED): recent_dlq_readable ${label} -> ${wantHealthy === "true"}`,
      isOperationallyHealthy(body.operational) === (wantHealthy === "true"), label);
  }

  fs.rmSync(tmpDir, { recursive: true, force: true });

  // The workflow must WIRE the strict entrypoint and must NOT carry the fragile jq
  // default that collapses booleans — so a revert to inline jq is caught here.
  const yml = fs.readFileSync(path.join(root, ".github/workflows/ops-deadman.yml"), "utf8");
  ok("workflow wires the strict entrypoint (shipped decision == tested evaluateDeadman)",
    yml.includes("scripts/ops-deadman-verdict.mjs"));
  ok("workflow no longer uses the fragile jq `// \"missing\"` boolean-collapsing default",
    !yml.includes('// "missing"'));
}

console.log(`\nF-027 internal observability: ${pass} passed, ${fail} failed`);
if (fail) process.exit(1);
