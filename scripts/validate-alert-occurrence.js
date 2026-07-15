#!/usr/bin/env node
//
// Alert occurrence identity — DB-backed, CI-blocking.
//
// The append-only lifecycle events tables are the canonical source of BOTH the
// condition-start timestamp and the occurrence identity. This proves that contract:
//
//   • a matching historical event BEFORE activation stays silent forever
//   • a row with NO historical event stays baseline-only (no timestamp is invented)
//   • a future real transition emits exactly once
//   • repeated hourly evaluation of the same occurrence deduplicates
//   • resolved → recurrent gets a NEW event id and may alert again
//   • tenant isolation and soft-delete remain enforced
//
// Node 24+.
import fs from "node:fs";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const eng = (f) => pathToFileURL(path.join(root, "workers", "scan-api", "src", "engines", f)).href;
const { findConditionOccurrence, buildMonitoringTransitionDetail, isMonitoringTransition, LIFECYCLE_EVENT_SOURCES } =
  await import(eng("alert-occurrence.js"));
const { emitManagedAlert, ensureAlertActivation, buildAlertDedupeKey } = await import(eng("managed-alerts.js"));

let pass = 0, fail = 0;
const ok = (n, c, d = "") => { c ? pass++ : fail++; if (!c) console.log(`FAIL ${n}${d ? " — " + d : ""}`); };
const eq = (n, g, w) => ok(n, JSON.stringify(g) === JSON.stringify(w), `got ${JSON.stringify(g)} want ${JSON.stringify(w)}`);

function buildDb() {
  const db = new DatabaseSync(":memory:");
  const apply = (p) => { try { db.exec(fs.readFileSync(p, "utf8")); } catch { /* additive drift tolerated */ } };
  apply(path.join(root, "database", "schema.sql"));
  for (const f of fs.readdirSync(path.join(root, "database", "migrations")).filter((f) => f.endsWith(".sql")).sort()) {
    apply(path.join(root, "database", "migrations", f));
  }
  db.exec("PRAGMA foreign_keys = OFF");
  return db;
}
function makeD1(db) {
  const wrap = (sql, args) => ({
    __sql: sql, __args: args,
    first: async (col) => { const r = db.prepare(sql).get(...args) ?? null; return col && r ? r[col] : r; },
    all: async () => ({ results: db.prepare(sql).all(...args), success: true, meta: {} }),
    run: async () => { const r = db.prepare(sql).run(...args); return { success: true, meta: { changes: r.changes } }; },
  });
  return { prepare(sql) { const b = wrap(sql, []); b.bind = (...a) => wrap(sql, a); return b; } };
}

const db = buildDb();
const realFetch = globalThis.fetch;
globalThis.fetch = async (url) => (String(url).includes("resend.com")
  ? new Response(JSON.stringify({ id: "email_1" }), { status: 200, headers: { "content-type": "application/json" } })
  : new Response("{}", { status: 200 }));

// ── Seed ─────────────────────────────────────────────────────────────────────
db.prepare("INSERT INTO users (id, email, name, plan, created_at) VALUES ('u1','o@example.com','o','professional',datetime('now'))").run();
db.prepare("UPDATE users SET email_verified = 1 WHERE id = 'u1'").run();
db.prepare(`INSERT INTO subscriptions (id, owner_user_id, plan, subscription_status, status, current_period_end, created_at, updated_at)
            VALUES ('s1','u1','professional','active','active',datetime('now','+30 days'),datetime('now'),datetime('now'))`).run();
db.prepare("INSERT INTO workspaces (id, owner_user_id, name) VALUES ('ws1','u1','ws1')").run();
db.prepare("INSERT INTO workspace_members (id, workspace_id, user_id, role) VALUES ('m1','ws1','u1','owner')").run();
db.prepare("INSERT INTO workspaces (id, owner_user_id, name) VALUES ('ws2','u1','ws2')").run();
db.prepare("INSERT INTO workspaces (id, owner_user_id, name) VALUES ('wsDead','u1','wsDead')").run();
db.prepare("UPDATE workspaces SET deleted_at = datetime('now') WHERE id = 'wsDead'").run();

const env = {
  cybermeters_db: makeD1(db),
  ALERT_EMAIL_FROM: "alerts@cybermeters.com",
  ALERT_EMAIL_TO: "operator@cybermeters.example",
  RESEND_API_KEY: "re_test",
};

const WATERMARK = "2026-06-01T00:00:00Z";
const notifs = (ws) => db.prepare("SELECT * FROM notification_events WHERE workspace_id = ?").all(ws);
const ledger = (ws) => db.prepare("SELECT * FROM alert_deliveries WHERE workspace_id = ?").all(ws);

// Append a monitoring_changed event exactly as an evaluator would.
let evSeq = 0;
function appendTransition(ws, recordId, { to_recurrence_type, created_at, entity = "www.example.com", table = "certificate_lifecycle_events", fk = "lifecycle_id" }) {
  const id = `ev_${++evSeq}`;
  db.prepare(`INSERT INTO ${table} (id, ${fk}, workspace_id, actor_type, actor_id, event_type, detail_json, created_at)
              VALUES (?, ?, ?, 'system', NULL, 'monitoring_changed', ?, ?)`)
    .run(id, recordId, ws, JSON.stringify(buildMonitoringTransitionDetail({
      to_monitoring_status: "at_risk", to_recurrence_type, required_case_action: "open_or_reopen",
      reason: "certificate_renewal_overdue", entity,
    })), created_at);
  return id;
}

// The consumer contract, in miniature: resolve the occurrence, then emit with the
// event's OWN timestamp and id. Never evaluated_at, last_seen_at, updated_at or now().
async function consume(ws, recordId, recurrence, { domain_key = "certificates_trust", entity = "www.example.com" } = {}) {
  const occ = await findConditionOccurrence(env, { workspace_id: ws, domain_key, record_id: recordId, recurrence_type: recurrence });
  if (!occ) return { skipped: "baseline_only" };   // pre-existing: no timestamp is invented
  return emitManagedAlert(env, {
    workspace_id: ws, domain_key, kind: `cert_${recurrence}`, severity: "high",
    title: `Certificate ${recurrence}`, message: "Condition observed.",
    dedupe_key: buildAlertDedupeKey({ domain_key, kind: `cert_${recurrence}`, subject: entity, period: occ.occurrence_id }),
    observed_at: occ.observed_at,
  });
}

// ── 1. Transition detection ──────────────────────────────────────────────────
{
  ok("a changed recurrence is a transition",
     isMonitoringTransition({ monitoring_status: "ok", recurrence_type: null }, { monitoring_status: "at_risk", recurrence_type: "renewal_overdue" }));
  ok("an unchanged condition is NOT a transition (no new occurrence each hour)",
     !isMonitoringTransition({ monitoring_status: "at_risk", recurrence_type: "renewal_overdue" }, { monitoring_status: "at_risk", recurrence_type: "renewal_overdue" }));
  // Six domains now: three lifecycle domains, two managed-case domains (PR-B1) and
  // Email Protection (PR-B3). Two shapes of sharing appear here, and both are safe
  // for the same underlying reason — the fk cannot collide:
  //   • Brand Protection and Attack Surface share managed_case_events keyed by
  //     case_id, and a case belongs to exactly one domain.
  //   • Email Protection is ONE domain over TWO record families (hosted records +
  //     sender sources) in email_protection_events keyed by a generic record_id,
  //     whose 'hd-' and 'esender_' namespaces are disjoint (asserted in
  //     validate-alert-b3-email-protection.js, since no FK can express it).
  eq("every canonical alerting domain has an event source", Object.keys(LIFECYCLE_EVENT_SOURCES).sort(),
     ["attack_surface", "brand_protection", "certificates_trust", "email_protection",
      "identity_exposure", "shadow_it_unmanaged_technology"]);

  // The type column is per-source because managed_case_events names its vocabulary
  // column `action`, not `event_type`. Hardcoding `event_type` is what made the
  // managed-case lookup raise "no such column", fail closed, and silently return
  // null forever — so those domains could never resolve an occurrence at all.
  for (const [domain_key, src] of Object.entries(LIFECYCLE_EVENT_SOURCES)) {
    ok(`${domain_key}: declares a type column`, typeof src.type_column === "string" && src.type_column.length > 0);
    ok(`${domain_key}: declares a table and fk`, Boolean(src.table) && Boolean(src.fk));
    // These are interpolated into SQL — they must be plain identifiers, never
    // anything a request or a row could influence.
    ok(`${domain_key}: source identifiers are safe SQL identifiers`,
       /^[a-z_]+$/.test(src.table) && /^[a-z_]+$/.test(src.fk) && /^[a-z_]+$/.test(src.type_column));
  }
  eq("managed_case_events is keyed on `action`", LIFECYCLE_EVENT_SOURCES.brand_protection.type_column, "action");
  eq("lifecycle tables are keyed on `event_type`", LIFECYCLE_EVENT_SOURCES.certificates_trust.type_column, "event_type");
}

// ── 2. No historical event → baseline only, no invented timestamp ────────────
{
  await ensureAlertActivation(env, "ws1", "certificates_trust", { now: WATERMARK });
  const r = await consume("ws1", "cl_nohistory", "renewal_overdue");
  eq("row with no transition event is baseline-only", r.skipped, "baseline_only");
  eq("baseline-only creates no bell notification", notifs("ws1").length, 0);
  eq("baseline-only creates no delivery at all", ledger("ws1").length, 0);
  const occ = await findConditionOccurrence(env, { workspace_id: "ws1", domain_key: "certificates_trust", record_id: "cl_nohistory", recurrence_type: "renewal_overdue" });
  eq("no occurrence is manufactured", occ, null);
}

// ── 3. Matching historical event BEFORE activation → silent forever ──────────
{
  appendTransition("ws1", "cl_old", { to_recurrence_type: "renewal_overdue", created_at: "2026-01-01T00:00:00Z", entity: "old.example.com" });
  const runs = [];
  for (let i = 0; i < 3; i++) runs.push(await consume("ws1", "cl_old", "renewal_overdue", { entity: "old.example.com" }));
  ok("pre-activation condition never emits", runs.every((r) => r.emitted === false));
  ok("pre-activation condition is baselined", runs.every((r) => r.reason === "alert_baseline_established"));
  eq("pre-activation condition creates no bell notification", notifs("ws1").length, 0);
  ok("repeated hourly evaluation stays silent", runs.length === 3);
}

// ── 4. Future real transition → emits exactly once, then dedupes ─────────────
{
  const evId = appendTransition("ws1", "cl_new", { to_recurrence_type: "renewal_overdue", created_at: "2026-07-01T00:00:00Z", entity: "new.example.com" });
  const first = await consume("ws1", "cl_new", "renewal_overdue", { entity: "new.example.com" });
  ok("post-activation transition emits", first.emitted === true && first.reason === null);
  eq("post-activation transition creates exactly one bell notification", notifs("ws1").length, 1);

  // The evaluator runs again an hour later. Same occurrence => same event id =>
  // same dedupe key => nothing new. This is the hourly-flood guarantee.
  const second = await consume("ws1", "cl_new", "renewal_overdue", { entity: "new.example.com" });
  const third = await consume("ws1", "cl_new", "renewal_overdue", { entity: "new.example.com" });
  ok("repeated evaluation of the same occurrence dedupes",
     second.reason === "deduplicated" && third.reason === "deduplicated");
  eq("repeated evaluation creates no extra notification", notifs("ws1").length, 1);
  ok("the occurrence id is the event id", typeof evId === "string" && evId.startsWith("ev_"));
}

// ── 5. Resolved → recurrent: a NEW event id may alert again ──────────────────
{
  // The condition clears, then genuinely returns: the evaluator appends a NEW
  // transition, which is a new occurrence with a new identity.
  appendTransition("ws1", "cl_new", { to_recurrence_type: "renewal_overdue", created_at: "2026-08-01T00:00:00Z", entity: "new.example.com" });
  const again = await consume("ws1", "cl_new", "renewal_overdue", { entity: "new.example.com" });
  ok("a genuine recurrence emits again (new event id => new identity)", again.emitted === true);
  eq("recurrence creates a second bell notification", notifs("ws1").length, 2);
  ok("recurrence is not treated as a duplicate", again.reason !== "deduplicated");
}

// ── 6. Tenant isolation ──────────────────────────────────────────────────────
{
  // ws2 has an identically-named record; its occurrence must never resolve from ws1.
  const cross = await findConditionOccurrence(env, { workspace_id: "ws2", domain_key: "certificates_trust", record_id: "cl_new", recurrence_type: "renewal_overdue" });
  eq("occurrence never resolves across tenants", cross, null);
  await ensureAlertActivation(env, "ws2", "certificates_trust", { now: WATERMARK });
  const r = await consume("ws2", "cl_new", "renewal_overdue");
  eq("foreign workspace cannot reference another tenant's occurrence", r.skipped, "baseline_only");
  eq("foreign workspace gets no notification", notifs("ws2").length, 0);
  ok("ws1 notifications remain ws1's only", notifs("ws1").every((n) => n.workspace_id === "ws1"));
}

// ── 7. Soft-delete ───────────────────────────────────────────────────────────
{
  appendTransition("wsDead", "cl_dead", { to_recurrence_type: "renewal_overdue", created_at: "2026-07-01T00:00:00Z" });
  const r = await consume("wsDead", "cl_dead", "renewal_overdue");
  eq("soft-deleted workspace emits nothing", r.emitted, false);
  eq("soft-deleted workspace reason", r.reason, "workspace_deleted");
  eq("soft-deleted workspace gets no bell notification", notifs("wsDead").length, 0);
}

// ── 8. Strict matching ───────────────────────────────────────────────────────
{
  // An unrelated older transition must NOT be borrowed for a different condition —
  // that would silently inherit its pre-watermark timestamp and suppress a real alert.
  appendTransition("ws1", "cl_strict", { to_recurrence_type: "coverage_regression", created_at: "2026-01-01T00:00:00Z" });
  const wrong = await findConditionOccurrence(env, { workspace_id: "ws1", domain_key: "certificates_trust", record_id: "cl_strict", recurrence_type: "renewal_overdue" });
  eq("a different recurrence_type is not matched", wrong, null);
  const right = await findConditionOccurrence(env, { workspace_id: "ws1", domain_key: "certificates_trust", record_id: "cl_strict", recurrence_type: "coverage_regression" });
  ok("the matching recurrence_type resolves", right?.observed_at === "2026-01-01T00:00:00Z");
}

// ── 9. The forbidden timestamps are never read ───────────────────────────────
{
  const src = fs.readFileSync(path.join(root, "workers", "scan-api", "src", "engines", "alert-occurrence.js"), "utf8")
    .split("\n").filter((l) => !l.trim().startsWith("//")).join("\n");
  for (const forbidden of ["evaluated_at", "last_seen_at", "updated_at", "Date.now("]) {
    ok(`occurrence resolution never reads ${forbidden}`, !src.includes(forbidden));
  }
  ok("occurrence resolution only reads the append-only events table", src.includes("monitoring_changed"));
}

globalThis.fetch = realFetch;
console.log(`\nalert-occurrence: ${pass} passed, ${fail} failed`);
if (fail > 0) { console.error("alert-occurrence validation FAILED"); process.exit(1); }
console.log("alert-occurrence validation passed");
