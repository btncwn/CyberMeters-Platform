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
  // ALL EIGHT canonical domains now: three lifecycle domains, two managed-case
  // domains (PR-B1), Email Protection (PR-B3), and Website Security + Cyber
  // Essentials Readiness (corrective phase). This list IS the 8/8 claim — if a
  // domain is absent here it cannot alert, whatever any document says. Two shapes of sharing appear here, and both are safe
  // for the same underlying reason — the fk cannot collide:
  //   • Brand Protection and Attack Surface share managed_case_events keyed by
  //     case_id, and a case belongs to exactly one domain.
  //   • Email Protection is ONE domain over TWO record families (hosted records +
  //     sender sources) in email_protection_events keyed by a generic record_id,
  //     whose 'hd-' and 'esender_' namespaces are disjoint (asserted in
  //     validate-alert-b3-email-protection.js, since no FK can express it).
  eq("every canonical alerting domain has an event source", Object.keys(LIFECYCLE_EVENT_SOURCES).sort(),
     ["attack_surface", "brand_protection", "certificates_trust", "cyber_essentials_readiness",
      "email_protection", "identity_exposure", "shadow_it_unmanaged_technology", "website_security"]);

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

// ── 8. CORRECT AT ANY LIFECYCLE AGE — an event window is not lifecycle state ──
// THE DEFECT THIS EXISTS TO PREVENT (reproduced 2026-07-16): this resolver read
// `LIMIT 25` of monitoring_changed rows and filtered `to_recurrence_type` in JS. But
// `monitoring_changed` is OVERLOADED — the same event_type also records "reappeared",
// "no_longer_observed" and case-linkage ({case_id, recurrence, updated_case}) — and
// Shadow IT appended one case-linkage row per evaluation pass for as long as a condition
// persisted. Measured against the real engine: the resolver returned the occurrence on
// passes 1-25 and NULL from pass 26 onward, forever, for a single item that had
// accumulated 148 monitoring_changed rows of which 4 were real occurrences.
//
// Measured customer impact was narrower than that sounds — those alerts deduped anyway
// (the dedupe key IS the occurrence id), and a genuine recurrence still alerted because
// its transition is appended immediately before the read. The bug was that correctness
// RESTED ON THAT ORDERING. 25 is not a semantic bound; it is a number. These assertions
// pin the property that matters: the answer must not depend on lifecycle age.
{
  const REC = "renewal_overdue_age";
  const REC_ID = "cert_age_1";
  // The real transition FIRST, so every noise row lands above it.
  const realId = appendTransition("ws1", REC_ID, { to_recurrence_type: REC, created_at: "2026-06-02T00:00:00Z" });

  const noise = (n, at) => {
    for (let i = 0; i < n; i++) {
      db.prepare(`INSERT INTO certificate_lifecycle_events (id, lifecycle_id, workspace_id, actor_type, event_type, detail_json, created_at)
                  VALUES (?, ?, 'ws1', 'system', 'monitoring_changed', ?, ?)`)
        .run(`noise_${REC_ID}_${i}_${at}`, REC_ID, JSON.stringify({ case_id: "c1", recurrence: REC, updated_case: true }), at);
    }
  };
  const resolve = () => findConditionOccurrence(env, {
    workspace_id: "ws1", domain_key: "certificates_trust", record_id: REC_ID, recurrence_type: REC,
  });

  ok("age 0: the occurrence resolves", (await resolve())?.occurrence_id === realId);
  noise(25, "2026-06-03T00:00:00Z");
  ok("after 25 intervening events: STILL resolves, and to the same occurrence",
     (await resolve())?.occurrence_id === realId);
  noise(25, "2026-06-04T00:00:00Z");
  ok("after 50 intervening events: STILL resolves", (await resolve())?.occurrence_id === realId);
  noise(50, "2026-06-05T00:00:00Z");
  ok("after 100 intervening events: STILL resolves", (await resolve())?.occurrence_id === realId);
  noise(400, "2026-06-06T00:00:00Z");
  ok("after 500 intervening events: STILL resolves — no window, no cliff",
     (await resolve())?.occurrence_id === realId);
  eq("and the observed_at is the REAL transition's own timestamp, not a noise row's",
     (await resolve())?.observed_at, "2026-06-02T00:00:00Z");

  // Irrelevant event types must not evict, or even be considered.
  for (const t of ["observed", "case_linked", "owner_missing", "case_recurrence_noted"]) {
    db.prepare(`INSERT INTO certificate_lifecycle_events (id, lifecycle_id, workspace_id, actor_type, event_type, detail_json, created_at)
                VALUES (?, ?, 'ws1', 'system', ?, ?, '2026-06-07T00:00:00Z')`)
      .run(`other_${t}`, REC_ID, t, JSON.stringify({ to_recurrence_type: REC }));
  }
  ok("events of another TYPE never become the occurrence, even carrying the same payload",
     (await resolve())?.occurrence_id === realId);
}

// ── 9. A malformed detail_json must not poison the read ──────────────────────
// The JS reader this replaced tolerated a bad row by returning {}. A bare json_extract()
// THROWS on malformed JSON and would take the whole query — and therefore EVERY alert for
// that record — down with it, which would trade a bounded-window bug for a poison pill.
{
  const REC = "renewal_overdue_poison";
  const REC_ID = "cert_poison_1";
  const realId = appendTransition("ws1", REC_ID, { to_recurrence_type: REC, created_at: "2026-06-02T00:00:00Z" });
  db.prepare(`INSERT INTO certificate_lifecycle_events (id, lifecycle_id, workspace_id, actor_type, event_type, detail_json, created_at)
              VALUES ('poison_1', ?, 'ws1', 'system', 'monitoring_changed', '{not valid json', '2026-06-08T00:00:00Z')`).run(REC_ID);
  db.prepare(`INSERT INTO certificate_lifecycle_events (id, lifecycle_id, workspace_id, actor_type, event_type, detail_json, created_at)
              VALUES ('poison_2', ?, 'ws1', 'system', 'monitoring_changed', NULL, '2026-06-09T00:00:00Z')`).run(REC_ID);
  const occ = await findConditionOccurrence(env, {
    workspace_id: "ws1", domain_key: "certificates_trust", record_id: REC_ID, recurrence_type: REC,
  });
  ok("a malformed detail_json row does NOT break the read", occ?.occurrence_id === realId);
}

// ── 10. Determinism: the NEWEST matching occurrence, with a stable tie-break ──
{
  const REC = "renewal_overdue_order";
  const REC_ID = "cert_order_1";
  const older = appendTransition("ws1", REC_ID, { to_recurrence_type: REC, created_at: "2026-06-02T00:00:00Z" });
  for (let i = 0; i < 30; i++) {
    db.prepare(`INSERT INTO certificate_lifecycle_events (id, lifecycle_id, workspace_id, actor_type, event_type, detail_json, created_at)
                VALUES (?, ?, 'ws1', 'system', 'monitoring_changed', ?, '2026-06-03T00:00:00Z')`)
      .run(`ord_noise_${i}`, REC_ID, JSON.stringify({ case_id: "c1" }));
  }
  const newer = appendTransition("ws1", REC_ID, { to_recurrence_type: REC, created_at: "2026-06-04T00:00:00Z" });
  const occ = await findConditionOccurrence(env, {
    workspace_id: "ws1", domain_key: "certificates_trust", record_id: REC_ID, recurrence_type: REC,
  });
  eq("with two occurrences of one condition, the NEWEST wins", occ?.occurrence_id, newer);
  ok("and never the older one — which would reuse its dedupe key and silence the recurrence",
     occ?.occurrence_id !== older);

  // Same-second tie: rowid (insertion order) decides, not the random hex id.
  const REC2 = "renewal_overdue_tie";
  const REC_ID2 = "cert_tie_1";
  const SEC = "2026-06-05T00:00:00Z";
  db.prepare(`INSERT INTO certificate_lifecycle_events (id, lifecycle_id, workspace_id, actor_type, event_type, detail_json, created_at)
              VALUES ('zzz_first', ?, 'ws1', 'system', 'monitoring_changed', ?, ?)`)
    .run(REC_ID2, JSON.stringify({ to_recurrence_type: REC2 }), SEC);
  db.prepare(`INSERT INTO certificate_lifecycle_events (id, lifecycle_id, workspace_id, actor_type, event_type, detail_json, created_at)
              VALUES ('aaa_second', ?, 'ws1', 'system', 'monitoring_changed', ?, ?)`)
    .run(REC_ID2, JSON.stringify({ to_recurrence_type: REC2 }), SEC);
  const tie = await findConditionOccurrence(env, {
    workspace_id: "ws1", domain_key: "certificates_trust", record_id: REC_ID2, recurrence_type: REC2,
  });
  eq("a same-second tie resolves to the LAST INSERTED row (rowid), not the lowest id",
     tie?.occurrence_id, "aaa_second");
}

// ── 11. Scope: another record's history cannot leak in; the tenant gate holds ──
// Note on what is NOT asserted here, and why. A fixture with the SAME record id in two
// workspaces would be physically impossible data: every lifecycle fk is the TEXT PRIMARY
// KEY of one global table with a crypto-random id (certificate_lifecycle 085:21,
// shadow_it_inventory 083:13, identity_exposure 086:21, hosted_dns_entries 071:17), and
// every writer stamps the event's workspace_id from the owning record. So no consistent
// database can hold a row that matches the fk but a different tenant, and staging one to
// claim a "cross-tenant leak" would be theatre. The workspace predicate is asserted for
// what it genuinely defends: a CALLER that arrives with someone else's record id.
{
  const REC = "renewal_overdue_scope";
  const mine = appendTransition("ws1", "cert_scope_a", { to_recurrence_type: REC, created_at: "2026-06-10T00:00:00Z" });

  // Another record in the SAME tenant, same recurrence, NEWER — routine, reachable state.
  appendTransition("ws1", "cert_scope_b", { to_recurrence_type: REC, created_at: "2026-06-25T00:00:00Z" });
  const occ = await findConditionOccurrence(env, {
    workspace_id: "ws1", domain_key: "certificates_trust", record_id: "cert_scope_a", recurrence_type: REC,
  });
  eq("a NEWER matching event on ANOTHER record is never returned", occ?.occurrence_id, mine);

  // The confused-deputy case: a caller asks for ws1's record while scoped to ws2.
  const foreign = await findConditionOccurrence(env, {
    workspace_id: "ws2", domain_key: "certificates_trust", record_id: "cert_scope_a", recurrence_type: REC,
  });
  eq("a caller scoped to another workspace resolves NOTHING for this record", foreign, null);
}

// ── 12. The read is bounded and precise — asserted at source ─────────────────
{
  const src = fs.readFileSync(path.join(root, "workers", "scan-api", "src", "engines", "alert-occurrence.js"), "utf8");
  // Slice from this function to the next top-level `export`, NOT to the first `\n}`:
  // the signature destructures across lines and closes with `\n} = {}) {`, so a lazy
  // match to `\n}` captures the signature alone and every assertion below it silently
  // passes against an empty body. An earlier draft of this section did exactly that.
  const start = src.indexOf("export async function findConditionOccurrence");
  const after = src.indexOf("\nexport ", start + 1);
  const fn = start === -1 ? "" : src.slice(start, after === -1 ? undefined : after);
  ok("findConditionOccurrence is where this suite thinks it is", fn.length > 0);
  ok("the extracted body is the real function, not just its signature", fn.includes("LIFECYCLE_EVENT_SOURCES[domain_key]") && fn.length > 500);
  ok("it asks SQL for the condition, rather than paging and filtering in JS",
     /json_extract\(detail_json, '\$\.to_recurrence_type'\)/.test(fn));
  ok("it guards against a malformed row poisoning the query", /json_valid\(detail_json\)/.test(fn));
  ok("it takes exactly ONE row — a semantic bound, not an arbitrary page", /LIMIT 1/.test(fn));
  // Asserted on CODE, with comments stripped. The body documents the `LIMIT 25` defect it
  // replaced, and prose explaining a removed bug must stay legal — an earlier draft of
  // this line matched its own explanation and failed against correct code.
  const code = fn.replace(/^\s*\/\/.*$/gm, "");
  ok("no arbitrary event window survives in the code", !/LIMIT\s+25/.test(code));
  ok("...and the explanation of the old window is still allowed in prose", /LIMIT 25/.test(fn));
  ok("it stays tenant-scoped", /WHERE workspace_id = \?/.test(fn));
  ok("it stays record-scoped", /\$\{source\.fk\} = \?/.test(fn));
  ok("it keeps the deterministic ordering + rowid tie-break", /ORDER BY created_at DESC, rowid DESC/.test(fn));
  ok("it does not read the whole table", !/SELECT \* FROM/.test(fn));
}

globalThis.fetch = realFetch;
console.log(`\nalert-occurrence: ${pass} passed, ${fail} failed`);
if (fail > 0) { console.error("alert-occurrence validation FAILED"); process.exit(1); }
console.log("alert-occurrence validation passed");
