#!/usr/bin/env node
// validate-scan-queue-dispatch.js
//
// PR-3A (22 Jul 2026 scan-lifecycle sequence): proves the durable manual-scan
// Queue dispatch — producer (queued admission + dispatch-setup compensation),
// consumer (claim CAS, at-least-once no-op semantics, fail-closed advisory
// checks), PR-1 recovery widening, and the config invariants — all while the
// cutover flag is OFF and the existing waitUntil path stays byte-identical.
//
// Layers:
//   A. Module contracts — mode flag fail-safe, v1 message shape, bounded delays.
//   B. Consumer behaviour — processScanDispatchMessage against an SQL-faithful
//      D1 stub (the claim guard applies ONLY if the SQL text carries it, so a
//      mutant that drops the CAS guard executes guardless here, exactly as
//      real D1 would) with injected engine/audit/heartbeat recorders.
//   C. Producer REAL-ROUTE behaviour — drives the actual scanRoutes handler
//      against a real SQLite database (schema + all migrations incl. the REAL
//      099 index), a recording R2 stub and a recording SCAN_QUEUE stub, in
//      BOTH dispatch modes.
//   D. Recovery integration — recoverInterruptedScans over queued rows.
//   E. Static/config contracts — wrangler queue config, workers_dev survives,
//      every SCAN_QUEUE send flows through the ONE dispatch boundary
//      (engines/scan-dispatch.js — PR-B1A routes scheduled sends through it
//      too), no third scan-creation path.
//
// Mutation directions (reverting the guard reddens the named assertion):
//   - consumer executes without the claim CAS guard   → B2 (exactly-one) fails
//   - queue-mode INSERT writes 'running' not 'queued' → C2 row-status fails
//   - producer emits scan_started in queue mode       → C2 audit-absence fails
//   - terminal redelivery enters the engine           → B3 fails
//   - recovery omits 'queued'                         → D1/D2 fail
//   - Queue.send / R2 failure without compensation    → C4/C5 fail
//   - broad DB errors converted to 409                → C7 fails
//   - waitUntil-mode behaviour changed                → C1 fails
//   - workers_dev changed or removed                  → E2 fails
//
// Node 24+ (node:sqlite). No network.

import fs from "node:fs";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const srcPath = (...p) => path.join(root, "workers", "scan-api", "src", ...p);

const {
  SCAN_DISPATCH_MESSAGE_VERSION,
  UNKNOWN_VERSION_RETRY_DELAY_S,
  TRANSIENT_RETRY_DELAY_S,
  DISPATCH_FAILED_REASON,
  isQueueDispatchMode,
  buildScanDispatchMessage,
  dispatchAdmittedScan,
  processScanDispatchMessage,
  handleScanDispatchBatch,
} = await import(pathToFileURL(srcPath("engines", "scan-dispatch.js")).href);
const {
  recoverInterruptedScans,
  RECOVERY_ACTIVE_STATUSES,
  RECOVERY_MIN_AGE_MS,
} = await import(pathToFileURL(srcPath("engines", "scan-recovery.js")).href);

let passed = 0, failed = 0;
function ok(name, cond, detail = "") {
  if (cond) { passed++; console.log(`PASS ${name}`); }
  else      { failed++; console.log(`FAIL ${name}${detail ? " — " + detail : ""}`); }
}

// ── Layer A: module contracts ────────────────────────────────────────────────
ok("A1 mode flag: only the exact string 'queue' enables dispatch (fail-safe)",
  isQueueDispatchMode({ SCAN_DISPATCH_MODE: "queue" }) === true &&
  isQueueDispatchMode({ SCAN_DISPATCH_MODE: "waituntil" }) === false &&
  isQueueDispatchMode({ SCAN_DISPATCH_MODE: "QUEUE" }) === false &&
  isQueueDispatchMode({ SCAN_DISPATCH_MODE: "" }) === false &&
  isQueueDispatchMode({}) === false &&
  isQueueDispatchMode(undefined) === false);

{
  const m = buildScanDispatchMessage({
    scanId: "scan_x1", workspaceId: "ws_x", domainId: "dom_x",
    domain: "fixture.example", userId: "user_x",
  });
  ok("A2 v1 message shape: version, authoritative scan_id, advisory identity, correlation",
    m.v === SCAN_DISPATCH_MESSAGE_VERSION && m.v === 1 &&
    m.scan_id === "scan_x1" && m.workspace_id === "ws_x" &&
    m.domain === "fixture.example" && m.domain_id === "dom_x" &&
    m.user_id === "user_x" && m.trigger === "manual" &&
    !Number.isNaN(Date.parse(m.admitted_at)) &&
    typeof m.request_id === "string" && m.request_id.length > 0);
  // PR-B1A byte-parity: a manual message carries NO scheduled_scan_id key and
  // its trigger defaults to "manual" (mutation direction: a producer that
  // stamps scheduled fields on manual messages reddens this).
  ok("A2b manual message is byte-parity: no scheduled_scan_id key, trigger manual",
    !("scheduled_scan_id" in m) && m.trigger === "manual");
}
ok("A3 retry delays are bounded and positive",
  Number.isInteger(UNKNOWN_VERSION_RETRY_DELAY_S) && UNKNOWN_VERSION_RETRY_DELAY_S > 0 && UNKNOWN_VERSION_RETRY_DELAY_S <= 3600 &&
  Number.isInteger(TRANSIENT_RETRY_DELAY_S) && TRANSIENT_RETRY_DELAY_S > 0 && TRANSIENT_RETRY_DELAY_S <= 3600);

// ── Layer B: consumer behaviour (SQL-faithful stub) ──────────────────────────
function makeConsumerHarness(rows) {
  const state = {
    rows: rows.map((r) => ({ ...r })),
    selects: 0, selectPoison: null, updatePoison: null,
    audits: [], stages: [], engineCalls: [],
    engineBehavior: null, // async (state, call) — simulate engine effects
  };
  const db = {
    prepare(sql) {
      return {
        bind(...args) {
          return {
            async first() {
              if (/SELECT[\s\S]*FROM scans WHERE id = \?/i.test(sql)) {
                if (state.selectPoison) throw state.selectPoison;
                state.selects++;
                const row = state.rows.find((r) => r.id === args[0]);
                return row ? { ...row } : null;
              }
              return null;
            },
            async run() {
              if (/UPDATE scans SET status = 'running'/i.test(sql)) {
                if (state.updatePoison) throw state.updatePoison;
                // SQL-faithful: the queued-only guard applies ONLY if the SQL
                // text actually carries it — a mutant that drops the CAS guard
                // runs guardless here, exactly as real D1 would.
                const hasGuard = /AND\s+status\s*=\s*'queued'/i.test(sql);
                const row = state.rows.find((r) => r.id === args[1]);
                if (!row) return { meta: { changes: 0 } };
                if (hasGuard && row.status !== "queued") return { meta: { changes: 0 } };
                row.status = "running";
                row.last_heartbeat_at = args[0];
                return { meta: { changes: 1 } };
              }
              return { meta: { changes: 0 } };
            },
            async all() { return { results: [] }; },
          };
        },
      };
    },
  };
  const env = { cybermeters_db: db, cybermeters_reports: { get: async () => null, put: async () => {} } };
  const deps = {
    createAuditEvent: async (_env, evt) => { state.audits.push(evt); },
    heartbeatScan: async (_env, id, stage) => { state.stages.push({ id, stage }); },
    runScanEngine: async (id, domainId, wsId, domain) => {
      const call = { id, domainId, wsId, domain };
      state.engineCalls.push(call);
      if (state.engineBehavior) await state.engineBehavior(state, call);
    },
  };
  return { env, deps, state };
}
const msgFor = (over = {}) => ({
  v: 1, scan_id: "scan_q1", workspace_id: "ws_q", domain: "queue-fixture.co.uk",
  domain_id: "dom_q", user_id: "user_q", trigger: "manual",
  admitted_at: "2026-07-22T10:00:00Z", request_id: "req_q1", ...over,
});
const QUEUED_ROW = { id: "scan_q1", workspace_id: "ws_q", domain_id: "dom_q", domain: "queue-fixture.co.uk", status: "queued" };

// B1 — happy path: claim wins, identity comes from the ROW, exactly one
// scan_started, queue_claimed heartbeat, engine invoked once, acked.
{
  const { env, deps, state } = makeConsumerHarness([{ ...QUEUED_ROW }]);
  const d = await processScanDispatchMessage(msgFor(), env, deps);
  const started = state.audits.filter((a) => a.event_type === "scan_started");
  ok("B1 happy path: queued → claimed → executed → ack",
    d.action === "ack" && d.outcome === "executed" &&
    state.rows[0].status === "running" &&
    state.engineCalls.length === 1 &&
    state.engineCalls[0].id === "scan_q1" &&
    state.engineCalls[0].domainId === "dom_q" &&
    state.engineCalls[0].wsId === "ws_q" &&
    state.engineCalls[0].domain === "queue-fixture.co.uk",
    JSON.stringify(d));
  ok("B1b exactly one scan_started, written by the CLAIM (not the producer)",
    started.length === 1 && started[0].entity_id === "scan_q1");
  ok("B1c queue_claimed heartbeat recorded",
    state.stages.some((s) => s.id === "scan_q1" && s.stage === "queue_claimed"));
}

// B2 — duplicate/simultaneous delivery: the CAS admits exactly ONE execution;
// the loser acks without executing and without a second scan_started.
{
  const { env, deps, state } = makeConsumerHarness([{ ...QUEUED_ROW }]);
  const d1 = await processScanDispatchMessage(msgFor(), env, deps); // row left 'running' (in-flight)
  const d2 = await processScanDispatchMessage(msgFor(), env, deps);
  ok("B2 duplicate delivery executes exactly once (CAS loser acks, never executes)",
    d1.outcome === "executed" && d2.action === "ack" && d2.outcome === "claim_lost" &&
    state.engineCalls.length === 1 &&
    state.audits.filter((a) => a.event_type === "scan_started").length === 1,
    `d2=${JSON.stringify(d2)} engines=${state.engineCalls.length}`);
}

// B3 — terminal redelivery is a no-op: no engine, no audit, no status change.
{
  for (const terminal of ["completed", "failed"]) {
    const { env, deps, state } = makeConsumerHarness([{ ...QUEUED_ROW, status: terminal }]);
    const d = await processScanDispatchMessage(msgFor(), env, deps);
    ok(`B3 terminal redelivery ('${terminal}') → ack no-op, engine never entered`,
      d.action === "ack" && d.outcome === "terminal_noop" &&
      state.engineCalls.length === 0 && state.audits.length === 0 &&
      state.rows[0].status === terminal);
  }
}

// B4 — malformed messages ack WITHOUT touching D1.
{
  const { env, deps, state } = makeConsumerHarness([{ ...QUEUED_ROW }]);
  const cases = [null, 42, "x", {}, { v: 1 }, { v: 1, scan_id: "" }, { v: 1, scan_id: 7 }];
  let allAck = true;
  for (const c of cases) {
    const d = await processScanDispatchMessage(c, env, deps);
    if (d.action !== "ack" || d.outcome !== "malformed") allAck = false;
  }
  ok("B4 malformed message → ack, no D1 read, no execution",
    allAck && state.selects === 0 && state.engineCalls.length === 0);
}

// B5 — unknown NEWER version retries with the bounded delay; nonsense acks.
{
  const { env, deps, state } = makeConsumerHarness([{ ...QUEUED_ROW }]);
  const newer = await processScanDispatchMessage(msgFor({ v: 2 }), env, deps);
  const junkA = await processScanDispatchMessage(msgFor({ v: 0 }), env, deps);
  const junkB = await processScanDispatchMessage(msgFor({ v: "two" }), env, deps);
  ok("B5 unknown newer version → bounded retry; nonsense version → malformed ack",
    newer.action === "retry" && newer.delaySeconds === UNKNOWN_VERSION_RETRY_DELAY_S &&
    junkA.action === "ack" && junkA.outcome === "malformed" &&
    junkB.action === "ack" && junkB.outcome === "malformed" &&
    state.engineCalls.length === 0);
}

// B6 — transient D1 read failure retries (never acks a scan away).
{
  const { env, deps, state } = makeConsumerHarness([{ ...QUEUED_ROW }]);
  state.selectPoison = new Error("D1_ERROR: storage operation exceeded its time limit");
  const d = await processScanDispatchMessage(msgFor(), env, deps);
  ok("B6 transient D1 read failure → retry with bounded delay",
    d.action === "retry" && d.delaySeconds === TRANSIENT_RETRY_DELAY_S &&
    state.engineCalls.length === 0);
}

// B7 — row missing → ack (nothing to execute or repair).
{
  const { env, deps, state } = makeConsumerHarness([]);
  const d = await processScanDispatchMessage(msgFor(), env, deps);
  ok("B7 missing scan row → ack row_missing, no execution",
    d.action === "ack" && d.outcome === "row_missing" && state.engineCalls.length === 0);
}

// B8 — advisory identity mismatch fails CLOSED: no execution, sanitised audit
// (field NAMES only, never the mismatched values), row untouched, ack.
{
  const { env, deps, state } = makeConsumerHarness([{ ...QUEUED_ROW }]);
  const d = await processScanDispatchMessage(msgFor({ workspace_id: "ws_FORGED" }), env, deps);
  const mm = state.audits.filter((a) => a.event_type === "scan_dispatch_mismatch");
  ok("B8 advisory mismatch → fail closed: ack, no execution, row untouched",
    d.action === "ack" && d.outcome === "advisory_mismatch" &&
    state.engineCalls.length === 0 && state.rows[0].status === "queued");
  ok("B8b mismatch audit carries field names, never values, and the ROW's tenant",
    mm.length === 1 && mm[0].workspace_id === "ws_q" &&
    JSON.stringify(mm[0].metadata.mismatched_fields) === JSON.stringify(["workspace_id"]) &&
    !JSON.stringify(mm[0].metadata).includes("ws_FORGED"));
}

// B9 — claim write failure retries.
{
  const { env, deps, state } = makeConsumerHarness([{ ...QUEUED_ROW }]);
  state.updatePoison = new Error("D1_ERROR: network");
  const d = await processScanDispatchMessage(msgFor(), env, deps);
  ok("B9 claim write failure → retry, no execution",
    d.action === "retry" && d.delaySeconds === TRANSIENT_RETRY_DELAY_S && state.engineCalls.length === 0);
}

// B10 — an engine THROW is acked, never retried: the engine's own finalisation
// (or PR-1 recovery) owns the terminal state; a redelivery could only re-run it.
{
  const { env, deps, state } = makeConsumerHarness([{ ...QUEUED_ROW }]);
  state.engineBehavior = () => { throw new Error("engine exploded"); };
  const d = await processScanDispatchMessage(msgFor(), env, deps);
  ok("B10 engine failure → ack (not retried); terminal ownership stays with the engine",
    d.action === "ack" && d.outcome === "engine_error" && state.engineCalls.length === 1);
}

// B11 — redelivery AFTER the engine self-finalised: terminal no-op, so a
// duplicate delivery can never duplicate findings/audits/notifications (every
// non-idempotent writer runs post-finalisation, gated behind this no-op).
{
  const { env, deps, state } = makeConsumerHarness([{ ...QUEUED_ROW }]);
  state.engineBehavior = (s) => { s.rows[0].status = "completed"; };
  await processScanDispatchMessage(msgFor(), env, deps);
  const auditsAfterFirst = state.audits.length;
  const d2 = await processScanDispatchMessage(msgFor(), env, deps);
  ok("B11 redelivery after completion → no second execution, ZERO additional audits",
    d2.action === "ack" && d2.outcome === "terminal_noop" &&
    state.engineCalls.length === 1 && state.audits.length === auditsAfterFirst);
}

// B12 — handleScanDispatchBatch applies the decision to the real message API.
{
  const { env, deps } = makeConsumerHarness([{ ...QUEUED_ROW }]);
  const events = [];
  const mkMsg = (body) => ({
    body, attempts: 1,
    ack: () => events.push({ type: "ack", body }),
    retry: (o) => events.push({ type: "retry", o, body }),
  });
  await handleScanDispatchBatch(
    { messages: [mkMsg(msgFor()), mkMsg(msgFor({ v: 5 })), mkMsg(null)] },
    env, {}, deps
  );
  ok("B12 batch handler: executed→ack, unknown version→retry(delay), malformed→ack",
    events.length === 3 &&
    events[0].type === "ack" &&
    events[1].type === "retry" && events[1].o?.delaySeconds === UNKNOWN_VERSION_RETRY_DELAY_S &&
    events[2].type === "ack");
}

// ── Layer C: producer real-route behaviour ───────────────────────────────────
const { scanRoutes } = await import(pathToFileURL(srcPath("routes", "scans.js")).href);
const { normalizeApiResponseData } = await import(pathToFileURL(srcPath("lib", "util.js")).href);

const cdb = new DatabaseSync(":memory:", { enableForeignKeyConstraints: false });
{
  const migDir = path.join(root, "database", "migrations");
  const apply = (p) => {
    try { cdb.exec(fs.readFileSync(p, "utf8")); }
    catch (e) { if (!/duplicate|already exists|no such (table|column)/i.test(e.message)) throw e; }
  };
  apply(path.join(root, "database", "schema.sql"));
  for (const f of fs.readdirSync(migDir).filter((x) => x.endsWith(".sql")).sort()) apply(path.join(migDir, f));
}

const FUTURE_ISO = new Date(Date.now() + 365 * 24 * 3600 * 1000).toISOString();
const FIXTURE_DOMAINS = ["qmode-a.co.uk", "qmode-b.co.uk", "qmode-c.co.uk", "qmode-d.co.uk", "qmode-e.co.uk", "wmode-a.co.uk"];
cdb.exec(`
  INSERT INTO workspaces (id, name, owner_user_id) VALUES ('ws_C', 'WS C', 'user_C1');
  INSERT INTO subscriptions (id, owner_user_id, plan, status, subscription_status, current_period_end)
    VALUES ('sub_C_1', 'user_C1', 'business', 'active', 'active', '${FUTURE_ISO}');
`);
FIXTURE_DOMAINS.forEach((d, i) => {
  cdb.prepare("INSERT INTO domains (id, user_id, domain) VALUES (?, 'user_C1', ?)").run(`dom_C_${i}`, d);
  cdb.prepare("INSERT INTO workspace_domains (workspace_id, domain_id, verification_status) VALUES ('ws_C', ?, 'verified')").run(`dom_C_${i}`);
});

const cState = {
  r2Puts: [], r2Poison: null,
  sends: [], sendPoison: null,
  insertPoison: null, updatePoison: null,
  waitUntils: [], engineParks: 0,
};
function cD1Adapter(sqlite) {
  const exec = (sql, args) => ({
    async first() { poke(sql); const r = sqlite.prepare(sql).get(...args); return r === undefined ? null : r; },
    async all()   { poke(sql); return { results: sqlite.prepare(sql).all(...args) }; },
    async run()   {
      // Park the ENGINE's own first write forever (waitUntil mode) so the real
      // scan engine never proceeds to network phases in this harness. The
      // consumer claim CAS carries `AND status = 'queued'` and is NOT parked.
      if (/^UPDATE scans SET status = 'running' WHERE id = \?$/.test(sql.trim())) {
        cState.engineParks++;
        return new Promise(() => {});
      }
      poke(sql);
      const info = sqlite.prepare(sql).run(...args);
      return { meta: { changes: Number(info.changes) } };
    },
  });
  const poke = (sql) => {
    if (cState.insertPoison && /INSERT INTO scans/.test(sql)) throw cState.insertPoison;
    if (cState.updatePoison && /UPDATE scans SET status = 'failed'/.test(sql)) throw cState.updatePoison;
  };
  return { prepare(sql) { const noArgs = exec(sql, []); return { ...noArgs, bind(...args) { return exec(sql, args); } }; } };
}
function makeProducerEnv(mode) {
  return {
    cybermeters_db: cD1Adapter(cdb),
    cybermeters_reports: {
      put: async (k, body) => {
        if (cState.r2Poison) throw cState.r2Poison;
        cState.r2Puts.push({ key: k, body: JSON.parse(body) });
      },
      get: async () => null,
    },
    SCAN_QUEUE: {
      send: async (m) => {
        cState.sends.push(m);
        if (cState.sendPoison) throw cState.sendPoison;
      },
    },
    ...(mode ? { SCAN_DISPATCH_MODE: mode } : {}),
  };
}
async function postScan(domain, mode) {
  const rctx = {
    request: { method: "POST", json: async () => ({ domain, workspace_id: "ws_C" }) },
    env: makeProducerEnv(mode),
    ctx: { waitUntil: (p) => { cState.waitUntils.push(p); } },
    url: new URL("https://api.test/api/scan"),
    json: (data, status = 200) => ({ data: normalizeApiResponseData(data, status), status }),
    serverError: () => ({ data: { error: "Request failed. Please try again." }, status: 500 }),
    corsHeaders: {},
    requireAuth: async () => ({ id: "user_C1" }),
    requireWorkspaceRole: async () => true,
    consumeApiRateLimit: async () => null,
    requireScanReadAccess: async () => null,
    getAccessibleWorkspaceIds: async () => ["ws_C"],
    computeNextRunAt: () => FUTURE_ISO,
  };
  return scanRoutes(rctx);
}
const cAudits = () => Object.fromEntries(
  cdb.prepare("SELECT event_type, COUNT(*) c FROM audit_events GROUP BY event_type").all().map((r) => [r.event_type, r.c]));
const scanRow = (domain) => cdb.prepare(
  "SELECT id, status, scan_quality FROM scans WHERE workspace_id='ws_C' AND domain=? ORDER BY created_at DESC LIMIT 1").get(domain);

// C1 — flag OFF: the existing waitUntil path is byte-identical (running row,
// running placeholder, scan_started audit, engine via ctx.waitUntil, 202).
{
  const r = await postScan("wmode-a.co.uk");
  const row = scanRow("wmode-a.co.uk");
  const a = cAudits();
  ok("C1 flag OFF preserves the waitUntil path exactly",
    r?.status === 202 && r.data.status === "running" &&
    row?.status === "running" &&
    cState.r2Puts.length === 1 && cState.r2Puts[0].body.status === "running" &&
    cState.waitUntils.length === 1 && cState.engineParks === 1 &&
    cState.sends.length === 0 &&
    (a.scan_requested || 0) === 1 && (a.scan_started || 0) === 1,
    `status=${r?.status} row=${JSON.stringify(row)} audits=${JSON.stringify(a)}`);
}

// C2 — flag ON: queued admission, queued placeholder (quality NULL), one v1
// send, 202 queued, NO waitUntil, NO producer scan_started.
{
  const before = cAudits();
  const r = await postScan("qmode-a.co.uk", "queue");
  const row = scanRow("qmode-a.co.uk");
  const a = cAudits();
  const put = cState.r2Puts[cState.r2Puts.length - 1];
  ok("C2 queue admission → row status 'queued' (never 'running')",
    row?.status === "queued", JSON.stringify(row));
  ok("C2b queued R2 placeholder: status queued, scan_quality null",
    put?.body?.status === "queued" && put.body.scan_quality === null &&
    put.key === `reports/${row?.id}.json`);
  ok("C2c exactly one v1 Queue message, scan_id matches the admitted row",
    cState.sends.length === 1 && cState.sends[0].v === 1 &&
    cState.sends[0].scan_id === row?.id &&
    cState.sends[0].workspace_id === "ws_C" && cState.sends[0].domain === "qmode-a.co.uk");
  ok("C2d 202 response: status queued, scan_quality null, honest queued wording",
    r?.status === 202 && r.data.status === "queued" && r.data.scan_quality === null &&
    r.data.scan_id === row?.id && /queued/i.test(r.data.message));
  ok("C2e producer emitted NO scan_started and NO engine start (consumer owns both)",
    (a.scan_started || 0) === (before.scan_started || 0) &&
    cState.waitUntils.length === 1 && cState.engineParks === 1 &&
    (a.scan_requested || 0) === (before.scan_requested || 0) + 1);
}

// C3 — duplicate queue-mode request → canonical 409, byte-exact body, nothing sent.
{
  const sendsBefore = cState.sends.length;
  const auditsBefore = cAudits();
  const r = await postScan("qmode-a.co.uk", "queue");
  ok("C3 duplicate queue-mode admission → canonical 409 { code, error }, no dispatch",
    r?.status === 409 &&
    JSON.stringify(Object.keys(r.data).sort()) === JSON.stringify(["code", "error"]) &&
    r.data.code === "active_scan_exists" &&
    r.data.error === "A scan is already active for this domain." &&
    cState.sends.length === sendsBefore &&
    JSON.stringify(cAudits()) === JSON.stringify(auditsBefore));
}

// C4 — Queue.send failure → full compensation: row failed (quality NULL),
// failed R2 report with reason dispatch_failed, one audit, customer-safe 503.
{
  cState.sendPoison = new Error("queue unavailable");
  const r = await postScan("qmode-b.co.uk", "queue");
  cState.sendPoison = null;
  const row = scanRow("qmode-b.co.uk");
  const lastPut = cState.r2Puts[cState.r2Puts.length - 1];
  const a = cAudits();
  ok("C4 Queue.send failure → row CAS-failed with scan_quality NULL",
    row?.status === "failed" && row.scan_quality === null, JSON.stringify(row));
  ok("C4b canonical failed R2 report written with reason dispatch_failed",
    lastPut?.body?.status === "failed" && lastPut.body.reason === DISPATCH_FAILED_REASON &&
    lastPut.body.scan_quality === null);
  // The 503 serializes through the REAL middleware, which decorates every
  // error body to the uniform { error, code, message } contract — assert that
  // exact shape and that no internal detail leaks through any value.
  ok("C4c one scan_dispatch_failed audit + customer-safe 503 (no internals)",
    (a.scan_dispatch_failed || 0) === 1 &&
    r?.status === 503 &&
    JSON.stringify(Object.keys(r.data).sort()) === JSON.stringify(["code", "error", "message"]) &&
    r.data.error === "The scan could not be started. Please try again." &&
    !/queue|D1|SQL|internal|stack/i.test(JSON.stringify(r.data)));
}

// C5 — R2 placeholder failure (R2 fully down): row still CAS-failed, no
// invented report over a broken store, 503.
{
  cState.r2Poison = new Error("r2 unavailable");
  const putsBefore = cState.r2Puts.length;
  const r = await postScan("qmode-c.co.uk", "queue");
  cState.r2Poison = null;
  const row = scanRow("qmode-c.co.uk");
  const a = cAudits();
  ok("C5 R2 failure → row failed, NO report invented over a broken store, 503",
    r?.status === 503 && row?.status === "failed" && row.scan_quality === null &&
    cState.r2Puts.length === putsBefore &&
    (a.scan_dispatch_failed || 0) === 2);
}

// C6 — compensation D1 failure: never fabricate success; 503 returned and the
// stale queued row is LEFT for PR-1 recovery.
{
  cState.sendPoison = new Error("queue unavailable");
  cState.updatePoison = new Error("D1_ERROR: network");
  const r = await postScan("qmode-d.co.uk", "queue");
  cState.sendPoison = null;
  cState.updatePoison = null;
  const row = scanRow("qmode-d.co.uk");
  ok("C6 compensation D1 failure → still 503, stale 'queued' row left for recovery",
    r?.status === 503 && row?.status === "queued" && row.scan_quality === null,
    JSON.stringify(row));
  // Clean up the deliberately-stale row so later fixtures are unaffected.
  cdb.prepare("UPDATE scans SET status='failed' WHERE workspace_id='ws_C' AND domain='qmode-d.co.uk'").run();
}

// C7 — an unexpected (non-constraint) INSERT failure in queue mode propagates
// as a real failure — NEVER converted to the 409 admission conflict.
{
  cState.insertPoison = new Error("D1_ERROR: no such table: scans");
  let threw = false, resp = null;
  try { resp = await postScan("qmode-e.co.uk", "queue"); } catch { threw = true; }
  cState.insertPoison = null;
  ok("C7 unexpected DB failure is NOT converted to active_scan_exists",
    threw || (resp && resp.status !== 409 && resp.status !== 202 && resp?.data?.code !== "active_scan_exists"));
}

// ── Layer D: PR-1 recovery integration ───────────────────────────────────────
ok("D1 RECOVERY_ACTIVE_STATUSES is exactly ['queued','running'] (widened, no 'retrying')",
  JSON.stringify(RECOVERY_ACTIVE_STATUSES) === JSON.stringify(["queued", "running"]));

function makeRecoveryEnv({ scans, r2Objects }) {
  const state = { scans: scans.map((s) => ({ ...s })), r2: new Map(Object.entries(r2Objects || {})), r2Puts: [], audits: [] };
  const db = {
    prepare(sql) {
      return {
        bind(...args) {
          return {
            async all() {
              if (/SELECT[\s\S]*FROM scans/i.test(sql)) {
                const statuses = args;
                const results = state.scans.filter((s) => statuses.includes(s.status)).map((s) => ({ ...s }));
                return { results };
              }
              return { results: [] };
            },
            async run() {
              if (/INSERT INTO audit_events/i.test(sql)) { state.audits.push(args); return { meta: { changes: 1 } }; }
              if (/UPDATE scans SET status = 'failed'/i.test(sql)) {
                const hasGuard = /AND\s+status\s+IN/i.test(sql);
                const row = state.scans.find((s) => s.id === args[0] && (!hasGuard || args.slice(1).includes(s.status)));
                if (!row) return { meta: { changes: 0 } };
                row.status = "failed";
                if (/scan_quality\s*=\s*NULL/i.test(sql)) row.scan_quality = null;
                return { meta: { changes: 1 } };
              }
              if (/UPDATE scans SET status = \?/i.test(sql)) {
                const hasGuard = /AND\s+status\s+IN/i.test(sql);
                const [status, score, rating, quality, id, ...statuses] = args;
                const row = state.scans.find((s) => s.id === id && (!hasGuard || statuses.includes(s.status)));
                if (!row) return { meta: { changes: 0 } };
                Object.assign(row, { status, score, rating, scan_quality: quality });
                return { meta: { changes: 1 } };
              }
              return { meta: { changes: 0 } };
            },
            async first() { return null; },
          };
        },
      };
    },
  };
  const r2 = {
    async get(key) {
      if (!state.r2.has(key)) return null;
      const v = state.r2.get(key);
      return { async json() { return JSON.parse(JSON.stringify(v)); } };
    },
    async put(key, body) { state.r2Puts.push({ key, body: JSON.parse(body) }); state.r2.set(key, JSON.parse(body)); },
  };
  return { env: { cybermeters_db: db, cybermeters_reports: r2 }, state };
}
const NOW = Date.parse("2026-07-22T12:00:00Z");
const agoSql = (ms) => new Date(NOW - ms).toISOString().replace("T", " ").slice(0, 19);
const STALE = RECOVERY_MIN_AGE_MS + 60 * 60 * 1000;

// D2 — stale queued row (never consumed; no heartbeat ever) → honest failed,
// quality NULL, ONE audit carrying status_before 'queued'.
{
  const { env, state } = makeRecoveryEnv({
    scans: [{ id: "scan_qstale", workspace_id: "ws_r", domain_id: "dom_r", domain: "r.example",
              status: "queued", created_at: agoSql(STALE), last_heartbeat_at: null }],
    r2Objects: { "reports/scan_qstale.json": { scan_id: "scan_qstale", status: "queued", findings: [] } },
  });
  const summary = await recoverInterruptedScans(env, { now: NOW });
  const row = state.scans[0];
  ok("D2 stale queued (never consumed) → failed, scan_quality NULL",
    summary.recovered_interrupted === 1 && row.status === "failed" && row.scan_quality === null,
    JSON.stringify({ summary, row }));
  ok("D2b exactly one recovery audit, evidencing status_before 'queued'",
    state.audits.length === 1 && JSON.stringify(state.audits[0]).includes('\\"status_before\\":\\"queued\\"') ||
    (state.audits.length === 1 && JSON.stringify(state.audits[0]).includes('"status_before":"queued"')),
    JSON.stringify(state.audits));
  ok("D2c R2 placeholder converged to an honest failed report (quality null)",
    state.r2Puts.length === 1 && state.r2Puts[0].body.status === "failed" &&
    state.r2Puts[0].body.scan_quality === null);
}

// D3 — a FRESH queued row is untouched: a message still inside its delivery/
// retry window can never be stolen from.
{
  const { env, state } = makeRecoveryEnv({
    scans: [{ id: "scan_qfresh", workspace_id: "ws_r", domain_id: "dom_r", domain: "r.example",
              status: "queued", created_at: agoSql(5 * 60 * 1000), last_heartbeat_at: null }],
    r2Objects: {},
  });
  const summary = await recoverInterruptedScans(env, { now: NOW });
  ok("D3 fresh queued row untouched (age gate holds for the queued class)",
    state.scans[0].status === "queued" && summary.recovered_interrupted === 0 && state.audits.length === 0);
}

// D4 — the original stale-running class still recovers (no regression from widening).
{
  const { env, state } = makeRecoveryEnv({
    scans: [{ id: "scan_rstale", workspace_id: "ws_r", domain_id: "dom_r", domain: "r.example",
              status: "running", created_at: agoSql(STALE), last_heartbeat_at: new Date(NOW - STALE).toISOString() }],
    r2Objects: { "reports/scan_rstale.json": { scan_id: "scan_rstale", status: "running", findings: [] } },
  });
  const summary = await recoverInterruptedScans(env, { now: NOW });
  ok("D4 stale running still recovers after the widening",
    summary.recovered_interrupted === 1 && state.scans[0].status === "failed");
}

// D5 — bridge: after recovery terminalised a queued scan, its late Queue
// delivery is a terminal no-op (the exact race the design must survive).
{
  const { env, deps, state } = makeConsumerHarness([{ ...QUEUED_ROW, status: "failed" }]);
  const d = await processScanDispatchMessage(msgFor(), env, deps);
  ok("D5 late delivery after recovery already failed the row → terminal no-op",
    d.action === "ack" && d.outcome === "terminal_noop" && state.engineCalls.length === 0);
}

// ── Layer E: static/config contracts ─────────────────────────────────────────
const wranglerSrc = fs.readFileSync(path.join(root, "workers", "scan-api", "wrangler.toml"), "utf8");
const stripToml = wranglerSrc.replace(/#[^\n]*/g, "");

// E1 — every send flows through the ONE dispatch boundary: the SCAN_QUEUE
// binding is consumed by engines/scan-dispatch.js and NOWHERE else in the
// Worker source. (PR-B1A: the scheduled producer sends via the SAME
// dispatchAdmittedScan compensation boundary — never via a direct binding
// reference of its own.)
{
  const files = [];
  const walk = (d) => {
    for (const e of fs.readdirSync(d, { withFileTypes: true })) {
      const p = path.join(d, e.name);
      if (e.isDirectory()) walk(p);
      else if (e.name.endsWith(".js") && fs.readFileSync(p, "utf8").includes("SCAN_QUEUE")) files.push(path.relative(root, p));
    }
  };
  walk(srcPath());
  ok("E1 SCAN_QUEUE is referenced ONLY by engines/scan-dispatch.js (the one dispatch boundary)",
    JSON.stringify(files) === JSON.stringify(["workers/scan-api/src/engines/scan-dispatch.js"]),
    JSON.stringify(files));
}

// E2 — wrangler config invariants (the release invariant + the approved queue shape).
ok("E2 workers_dev = true survives the config change (SSO redirect + rollback path)",
  /^workers_dev = true$/m.test(stripToml.replace(/\r/g, "")) || /^workers_dev = true\s*$/m.test(wranglerSrc));
ok("E2b producer binding SCAN_QUEUE → cybermeters-scan-dispatch",
  /\[\[queues\.producers\]\]\s*binding = "SCAN_QUEUE"\s*queue = "cybermeters-scan-dispatch"/.test(stripToml.replace(/\n+/g, "\n")));
ok("E2c consumer: batch 1, retries 3, concurrency 2, DLQ cybermeters-scan-dlq",
  /\[\[queues\.consumers\]\]/.test(stripToml) &&
  /max_batch_size = 1\b/.test(stripToml) &&
  /max_retries = 3\b/.test(stripToml) &&
  /max_concurrency = 2\b/.test(stripToml) &&
  /dead_letter_queue = "cybermeters-scan-dlq"/.test(stripToml));
// PR-3B (founder-approved cutover): the flag is now pinned ON. A silent
// config revert, a removed flag or a typo'd value all redden this — an
// intentional rollback must change this assertion in the same commit,
// keeping the deployed mode and its pin in lockstep.
ok("E2d cutover flag is present and ON (SCAN_DISPATCH_MODE = \"queue\")",
  /^SCAN_DISPATCH_MODE = "queue"$/m.test(stripToml.replace(/\r/g, "")));
ok("E2e custom-domain route and cron unchanged",
  /pattern = "api\.cybermeters\.com"/.test(wranglerSrc) &&
  /custom_domain = true/.test(wranglerSrc) &&
  /crons = \["0 \* \* \* \*"\]/.test(wranglerSrc));

// E3 — migration 099 already guards the queued state (real index, real DB):
// two queued admissions for one (workspace, domain) cannot coexist.
{
  cdb.prepare("INSERT INTO scans (id, domain_id, workspace_id, domain, status) VALUES ('scan_g1','dom_C_4','ws_C','guard-fixture.co.uk','queued')").run();
  let dupQueued = false, dupRunning = false;
  try { cdb.prepare("INSERT INTO scans (id, domain_id, workspace_id, domain, status) VALUES ('scan_g2','dom_C_4','ws_C','guard-fixture.co.uk','queued')").run(); }
  catch (e) { dupQueued = /UNIQUE constraint failed/i.test(e.message); }
  try { cdb.prepare("INSERT INTO scans (id, domain_id, workspace_id, domain, status) VALUES ('scan_g3','dom_C_4','ws_C','guard-fixture.co.uk','running')").run(); }
  catch (e) { dupRunning = /UNIQUE constraint failed/i.test(e.message); }
  ok("E3 099 guard: a queued admission blocks both a second queued AND a running insert",
    dupQueued && dupRunning);
}

// E4 — the consumer creates no scan rows (the two admission paths stay the
// only INSERTs; the admission validator's D6 count enforces the global rule).
ok("E4 scan-dispatch module performs no INSERT INTO scans",
  !fs.readFileSync(srcPath("engines", "scan-dispatch.js"), "utf8").includes("INSERT INTO scans"));

// E5 — producer source order: the queue branch returns BEFORE the waitUntil
// path's scan_started audit (scan_started is consumer-owned in queue mode).
{
  const sc = fs.readFileSync(srcPath("routes", "scans.js"), "utf8");
  const dispatchIdx = sc.indexOf("dispatchAdmittedScan(env");
  const startedIdx = sc.indexOf('"scan_started"');
  ok("E5 queue branch precedes the waitUntil scan_started audit in the route",
    dispatchIdx > -1 && startedIdx > dispatchIdx);
}

console.log(`\nscan-queue-dispatch: ${passed} passed, ${failed} failed`);
if (failed) { console.error("scan-queue-dispatch validation FAILED"); process.exit(1); }
console.log("scan-queue-dispatch validation passed");
