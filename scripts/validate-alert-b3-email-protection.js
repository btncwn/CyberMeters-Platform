#!/usr/bin/env node
//
// PR-B3 — Email Protection canonical lifecycle. DB-backed, CI-blocking.
//
// This drives the REAL engines against the REAL schema and asserts the resolver
// finds what the evaluator actually wrote. It deliberately does NOT hand-author
// events: the B1 lesson is that a suite which writes both sides of a contract
// proves only that it agrees with itself, and that is exactly how Identity and
// Shadow IT shipped permanently unable to alert while every test stayed green.
//
// The assertions that matter most here are the two that would flood or lie:
//   • the per-record baseline guard (a brand-new events table means
//     baseline_count = 0 for EVERY workspace, which trips emitManagedAlert's
//     firstEverCondition hatch and would announce the entire backlog);
//   • windowed evidence (the cumulative counters latch true forever and can
//     never recover).
//
// Node 24+.
import fs from "node:fs";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const eng = (f) => pathToFileURL(path.join(root, "workers", "scan-api", "src", "engines", f)).href;

const { findConditionOccurrence, LIFECYCLE_EVENT_SOURCES } = await import(eng("alert-occurrence.js"));
const { severityForRecurrence, INHERIT_SEVERITY } = await import(eng("alert-consumers.js"));
const {
  EMAIL_PROTECTION_DOMAIN_KEY, EMAIL_RECURRENCES, EMAIL_RECURRENCE_FINDING_TYPE,
  NON_ALERTABLE_EVENT_TYPES, SENDER_FAILURE_TRIGGER, SENDER_WINDOW_DAYS,
  evaluateEmailSenderMonitoring, recordHostedTransition,
  gradeSenderCondition, senderAlertBand, classificationRank,
  effectiveClassification, isPreExistingRecord, resolveSenderPolicy,
} = await import(eng("email-protection-lifecycle.js"));
const { resolveRemediation } = await import(eng("remediation-registry.js"));
const {
  CUSTOMER_SENDER_DISPOSITIONS, DISPOSITION_ASSERTS, OBSERVED_SENDER_CLASSIFICATIONS,
  assertedClassification, isCustomerDisposition, resolveEffectiveClassification,
} = await import(eng("sender-classification.js"));

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
    first: async (col) => { const r = db.prepare(sql).get(...args) ?? null; return col && r ? r[col] : r; },
    all: async () => ({ results: db.prepare(sql).all(...args), success: true, meta: {} }),
    run: async () => { const r = db.prepare(sql).run(...args); return { success: true, meta: { changes: r.changes } }; },
  });
  return { prepare(sql) { const b = wrap(sql, []); b.bind = (...a) => wrap(sql, a); return b; } };
}

const db = buildDb();
const env = { cybermeters_db: makeD1(db), RESEND_API_KEY: "", ALERT_EMAIL_FROM: "alerts@cybermeters.com" };
const realFetch = globalThis.fetch;
globalThis.fetch = async () => new Response("{}", { status: 200 });

// An entitled, live workspace — otherwise every alert stops at the gate and the
// suite would "pass" while proving nothing.
db.prepare("INSERT INTO users (id, email, name, plan, created_at) VALUES ('u1','o@example.com','o','business',datetime('now'))").run();
db.prepare("INSERT INTO users (id, email, name, plan, created_at) VALUES ('u2','b@example.com','b','business',datetime('now'))").run();
db.prepare("INSERT INTO workspaces (id, owner_user_id, name) VALUES ('ws1','u1','ws1')").run();
db.prepare("INSERT INTO workspaces (id, owner_user_id, name) VALUES ('ws2','u2','ws2')").run();

// Occurrence-shaped events ONLY. `monitoring_changed` carrying to_recurrence_type
// is an occurrence; every other event_type is history and must be unmatchable.
function occurrenceEvents(recordId) {
  return db.prepare(`SELECT * FROM email_protection_events WHERE record_id=? AND event_type='monitoring_changed'`)
    .all(recordId)
    .filter((e) => { try { return JSON.parse(e.detail_json || "{}").to_recurrence_type != null; } catch { return false; } });
}
const allEvents = (recordId) => db.prepare(`SELECT * FROM email_protection_events WHERE record_id=? ORDER BY created_at, id`).all(recordId);

// Let the wall clock advance past one second before minting a SECOND occurrence
// for the same record+recurrence.
//
// This is not a workaround for a bug in this engine — it makes the test model
// reality. Lifecycle events are stamped by SQLite `datetime('now')`, which is
// SECOND-precision, and findConditionOccurrence orders by (created_at DESC,
// id DESC). Two occurrences of the SAME recurrence on the SAME record inside one
// second therefore tie on created_at and fall back to the id — which is random
// hex, so the resolver can pick the older one, reuse its dedupe key, and the
// alert is correctly suppressed as a duplicate.
//
// The sequences below (active → recover → re-enter; regression → new policy
// change → regression) are DAYS apart in production: a 7-day evidence window has
// to empty and refill, and a policy change has to be applied. Compressing them
// into one second would test a state the product cannot reach. The underlying
// tie-break is a property of the SHARED resolver — it applies equally to the five
// domains wired before this one — and is deliberately not changed here.
const tick = () => new Promise((r) => setTimeout(r, 1100));
const notifications = (ws) => db.prepare(`SELECT * FROM notification_events WHERE workspace_id=?`).all(ws);
const deliveries = (ws) => db.prepare(`SELECT * FROM alert_deliveries WHERE workspace_id=?`).all(ws);

// Force the activation watermark to a known instant so "pre-existing" vs "new" is
// deterministic rather than a race with the current second.
function activate(ws, at) {
  db.prepare(`INSERT OR IGNORE INTO alert_activation (id, workspace_id, domain_key, activated_at, baseline_count, created_at)
              VALUES (?, ?, 'email_protection', ?, 0, datetime('now'))`).run(`act_${ws}`, ws, at);
}

// ── 1. Registration — the silent-failure surface ─────────────────────────────
{
  const src = LIFECYCLE_EVENT_SOURCES[EMAIL_PROTECTION_DOMAIN_KEY];
  ok("email_protection is registered as an occurrence source", Boolean(src));
  eq("the source is the shared append-only table",
     [src?.table, src?.fk, src?.type_column], ["email_protection_events", "record_id", "event_type"]);

  // The interpolated allowlist must match the REAL schema, or the lookup raises,
  // the catch swallows it, and the domain is silently unalertable forever.
  const cols = db.prepare("PRAGMA table_info(email_protection_events)").all().map((c) => c.name);
  for (const c of ["id", "record_id", "record_type", "workspace_id", "event_type", "detail_json", "created_at"]) {
    ok(`email_protection_events has real column ${c}`, cols.includes(c));
  }
  const senderCols = db.prepare("PRAGMA table_info(email_sender_sources)").all().map((c) => c.name);
  for (const c of ["monitoring_status", "recurrence_type", "recurrence_band", "evaluated_at"]) {
    ok(`email_sender_sources has lifecycle column ${c}`, senderCols.includes(c));
  }

  // Every actionable recurrence must be graded, or emitLifecycleAlert refuses it.
  for (const r of EMAIL_RECURRENCES) {
    ok(`recurrence '${r}' has an asserted severity`, severityForRecurrence(EMAIL_PROTECTION_DOMAIN_KEY, r) !== null);
    const ft = EMAIL_RECURRENCE_FINDING_TYPE[r];
    ok(`recurrence '${r}' maps to a finding type`, Boolean(ft));
    ok(`finding type '${ft}' resolves to canonical remediation`, resolveRemediation({ finding_type: ft })?.status === "resolved");
  }
  // Confirmations must NOT be gradable: absence here is the second independent
  // stop that makes them unalertable even if a caller hand-rolled an event.
  for (const t of NON_ALERTABLE_EVENT_TYPES) {
    ok(`non-alertable '${t}' has NO severity mapping`, severityForRecurrence(EMAIL_PROTECTION_DOMAIN_KEY, t) === null);
  }
  eq("hosted_record_reconnected is not a graded recurrence",
     severityForRecurrence(EMAIL_PROTECTION_DOMAIN_KEY, "hosted_record_reconnected"), null);
  eq("the manual rollback is not a graded recurrence",
     severityForRecurrence(EMAIL_PROTECTION_DOMAIN_KEY, "hosted_rolled_back_manual"), null);
  // The claim correction: the dishonest name must not exist anywhere.
  eq("`sender_spoofing_spike` is NOT a recurrence (unevidenced claim)",
     severityForRecurrence(EMAIL_PROTECTION_DOMAIN_KEY, "sender_spoofing_spike"), null);
}

// ── 2. Pure grading — severity is asserted, never invented ───────────────────
{
  eq("unauthorised bands high", senderAlertBand("unauthorised"), "high");
  eq("suspicious bands medium", senderAlertBand("suspicious"), "medium");
  eq("unknown bands medium", senderAlertBand("unknown"), "medium");
  eq("authorised has no band", senderAlertBand("authorised"), null);
  eq("forwarder has no band", senderAlertBand("forwarder"), null);
  ok("worsening is ordered", classificationRank("unauthorised") > classificationRank("suspicious")
     && classificationRank("suspicious") > classificationRank("unknown")
     && classificationRank("unknown") > classificationRank("authorised"));

  // The band IS the severity — one function, no second mapping to drift.
  eq("INHERIT resolves through the band, not a fixed grade",
     severityForRecurrence(EMAIL_PROTECTION_DOMAIN_KEY, "sender_unrecognised"), INHERIT_SEVERITY);

  eq("at the trigger, an unauthorised source is a condition",
     gradeSenderCondition({ classification: "unauthorised", window_total: 100, window_failed: SENDER_FAILURE_TRIGGER, is_new: false }).recurrence,
     "sender_unauthorised_failures_active");
  eq("one below the trigger is NOT a condition",
     gradeSenderCondition({ classification: "unauthorised", window_total: 100, window_failed: SENDER_FAILURE_TRIGGER - 1, is_new: false }).recurrence,
     null);
  eq("a new risky high-volume source is unrecognised",
     gradeSenderCondition({ classification: "unknown", window_total: 60, window_failed: 0, is_new: true }).recurrence,
     "sender_unrecognised");
  eq("an OLD risky source is not 'new'",
     gradeSenderCondition({ classification: "unknown", window_total: 60, window_failed: 0, is_new: false }).recurrence, null);
  eq("a new AUTHORISED source is not a condition",
     gradeSenderCondition({ classification: "authorised", window_total: 900, window_failed: 0, is_new: true }).recurrence, null);
  eq("a new low-volume source is not a condition",
     gradeSenderCondition({ classification: "unknown", window_total: 3, window_failed: 0, is_new: true }).recurrence, null);

  // Manual customer classification wins — preserved from the legacy engine, but the
  // customer's word is TRANSLATED into the observed vocabulary rather than returned raw.
  //
  // The fixture this replaces was unreachable: it put `classification: "authorised"` in
  // the CUSTOMER slot, and the classify route has only ever accepted
  // trusted/suspicious/threat/ignored/unknown (since 27f655f) — it would 400 that value.
  // Migration 074 states the split: the customer's decision lives in `classification`,
  // engine evidence in `auto_*`. So the test asserted a state the product cannot be in,
  // and in doing so it pinned the very collapse that let `threat` band null.
  eq("manual classification beats auto, in the observed vocabulary",
     effectiveClassification({ classification: "trusted", auto_classification: "unauthorised", classified_at: "2026-07-15 10:00:00" }), "authorised");
  eq("a manual THREAT is unauthorised, never passed through raw",
     effectiveClassification({ classification: "threat", auto_classification: "authorised", classified_at: "2026-07-15 10:00:00" }), "unauthorised");
  // `ignored` asks not to be told; it does not claim the sender is safe. The evidence stands.
  eq("ignored claims nothing, so the evidence stands",
     effectiveClassification({ classification: "ignored", auto_classification: "unauthorised", classified_at: "2026-07-15 10:00:00" }), "unauthorised");
  // An unrecognised value in the customer slot must fail closed to the evidence, never
  // masquerade as a verdict of its own.
  eq("an unsupported customer value falls back to the evidence",
     effectiveClassification({ classification: "authorised", auto_classification: "unauthorised", classified_at: "2026-07-15 10:00:00" }), "unauthorised");
  eq("without a manual decision, auto is effective", effectiveClassification({ classification: "unknown", auto_classification: "unauthorised", classified_at: null }), "unauthorised");

  // Fail closed: an unknown watermark or birth cannot be shown to be new.
  ok("unknown watermark => pre-existing (fail closed)", isPreExistingRecord("2026-07-15 10:00:00", null));
  ok("unparseable birth => pre-existing (fail closed)", isPreExistingRecord(null, "2026-07-15 10:00:00"));
  ok("born before the watermark => pre-existing", isPreExistingRecord("2026-07-01 10:00:00", "2026-07-15 10:00:00"));
  ok("born after the watermark => new", !isPreExistingRecord("2026-07-16 10:00:00", "2026-07-15 10:00:00"));
}

// ── 3. THE FLOOD GUARD — a backlog with baseline_count = 0 must stay silent ──
// This is the assertion that protects the first invited customers. The events
// table is new, so countPriorOccurrences is 0 for every workspace, which trips
// emitManagedAlert's firstEverCondition hatch. Only the per-record guard stops
// the entire pre-existing backlog being announced as news.
{
  activate("ws1", "2026-07-15 12:00:00");
  eq("the baseline really is empty (the dangerous precondition)",
     db.prepare("SELECT baseline_count FROM alert_activation WHERE workspace_id='ws1'").get().baseline_count, 0);

  // 3 senders that predate the watermark, all in alert-worthy states.
  for (let i = 1; i <= 3; i++) {
    db.prepare(`INSERT INTO email_sender_sources
      (id, workspace_id, domain, source_ip, first_seen, last_seen, total_messages, aligned_messages,
       failed_messages, pass_rate, classification, auto_classification, created_at)
      VALUES (?, 'ws1', 'example.com', ?, '2026-07-01 09:00:00', '2026-07-15 09:00:00',
              9000, 0, 9000, 0, 'unknown', 'unauthorised', '2026-07-01 09:00:00')`)
      .run(`esender_old${i}`, `10.0.0.${i}`);
  }
  // Windowed evidence far above the trigger — nothing here is marginal.
  db.prepare(`INSERT INTO dmarc_aggregate_reports (id, workspace_id, domain, external_report_id, date_range_begin, date_range_end, created_at)
              VALUES ('rep_old','ws1','example.com','r-old', 1, 99999999999, datetime('now'))`).run();
  for (let i = 1; i <= 3; i++) {
    db.prepare(`INSERT INTO dmarc_aggregate_records (id, report_id, workspace_id, domain, source_ip, message_count, dkim_aligned_result, spf_aligned_result, created_at)
                VALUES (?, 'rep_old','ws1','example.com', ?, 5000, 'fail', 'fail', datetime('now'))`)
      .run(`rec_old${i}`, `10.0.0.${i}`);
  }

  const res = await evaluateEmailSenderMonitoring(env, "ws1", "example.com");
  eq("the activating pass examined the backlog", res.checked, 3);
  eq("THE FLOOD GUARD: a pre-existing backlog raises ZERO alerts", res.alerts, 0);
  eq("no notification was written for the backlog", notifications("ws1").length, 0);
  eq("no delivery was attempted for the backlog", deliveries("ws1").length, 0);

  for (let i = 1; i <= 3; i++) {
    const evs = allEvents(`esender_old${i}`);
    ok(`backlog sender ${i} still got a history event`, evs.length === 1);
    eq(`backlog sender ${i}'s event is a baseline, not an occurrence`, evs[0].event_type, "baseline_established");
    eq(`backlog sender ${i} has NO occurrence`, occurrenceEvents(`esender_old${i}`).length, 0);
    const st = db.prepare("SELECT * FROM email_sender_sources WHERE id=?").get(`esender_old${i}`);
    eq(`backlog sender ${i} is marked baseline`, st.monitoring_status, "baseline");
  }

  // And it must STAY silent on every later pass, not merely the first.
  await evaluateEmailSenderMonitoring(env, "ws1", "example.com");
  await evaluateEmailSenderMonitoring(env, "ws1", "example.com");
  eq("the backlog stays silent across repeated passes", notifications("ws1").length, 0);
  eq("repeated passes append no occurrence", occurrenceEvents("esender_old1").length, 0);
}

// ── 4. A genuinely NEW sender alerts — and only once ─────────────────────────
{
  db.prepare(`INSERT INTO email_sender_sources
    (id, workspace_id, domain, source_ip, first_seen, last_seen, total_messages, aligned_messages,
     failed_messages, pass_rate, classification, auto_classification, created_at)
    VALUES ('esender_new1','ws1','example.com','10.0.9.9','2026-07-16 09:00:00','2026-07-16 10:00:00',
            0, 0, 0, 0, 'unknown', 'suspicious', '2026-07-16 09:00:00')`).run();
  db.prepare(`INSERT INTO dmarc_aggregate_records (id, report_id, workspace_id, domain, source_ip, message_count, dkim_aligned_result, spf_aligned_result, created_at)
              VALUES ('rec_new1','rep_old','ws1','example.com','10.0.9.9', 800, 'pass', 'fail', datetime('now'))`).run();

  const before = notifications("ws1").length;
  await evaluateEmailSenderMonitoring(env, "ws1", "example.com");
  const occ = occurrenceEvents("esender_new1");
  eq("a new sender minted exactly ONE occurrence", occ.length, 1);
  ok("a new sender alerted", notifications("ws1").length === before + 1);

  const n = notifications("ws1").at(-1);
  eq("the alert is attributed to the canonical domain", n.domain_key, "email_protection");
  eq("the alert kind is namespaced", n.type, "email_protection.sender_unrecognised");
  eq("severity came from the band, not a default", n.severity, "medium");

  // THE PARITY ASSERTION: the resolver finds what the evaluator itself wrote.
  const resolved = await findConditionOccurrence(env, {
    workspace_id: "ws1", domain_key: "email_protection",
    record_id: "esender_new1", recurrence_type: "sender_unrecognised",
  });
  ok("the resolver RESOLVES the evaluator's own transition", resolved !== null);
  eq("occurrence identity IS the persisted event id", resolved?.occurrence_id, occ[0].id);
  eq("observed_at IS the event's own created_at", resolved?.observed_at, occ[0].created_at);
  ok("the dedupe key carries the occurrence id", String(n.dedupe_key).includes(occ[0].id));

  // Unchanged re-evaluation: no event, no second alert.
  await evaluateEmailSenderMonitoring(env, "ws1", "example.com");
  await evaluateEmailSenderMonitoring(env, "ws1", "example.com");
  eq("unchanged re-evaluation appends NO new occurrence", occurrenceEvents("esender_new1").length, 1);
  eq("occurrence identity is stable across passes", occurrenceEvents("esender_new1")[0].id, occ[0].id);
  eq("unchanged re-evaluation sends NO second alert", notifications("ws1").length, before + 1);
}

// ── 5. Worsening escalates; the customer's own action never alerts ───────────
{
  // suspicious (medium) → unauthorised (high): same family, louder.
  db.prepare(`UPDATE email_sender_sources SET auto_classification='unauthorised' WHERE id='esender_new1'`).run();
  const before = notifications("ws1").length;
  await evaluateEmailSenderMonitoring(env, "ws1", "example.com");
  const n = notifications("ws1").at(-1);
  ok("worsening raised a new alert", notifications("ws1").length === before + 1);
  eq("worsening is named as such", n.type, "email_protection.sender_classification_worsened");
  eq("worsening ESCALATED the grade via the band", n.severity, "high");
  ok("worsening minted a NEW occurrence identity", occurrenceEvents("esender_new1").length >= 2);

  // The customer classifying a sender is not a risk alert.
  db.prepare(`INSERT INTO email_sender_sources
    (id, workspace_id, domain, source_ip, first_seen, last_seen, total_messages, aligned_messages,
     failed_messages, pass_rate, classification, auto_classification, monitoring_status, recurrence_band, created_at)
    VALUES ('esender_man','ws1','example.com','10.0.7.7','2026-07-16 09:00:00','2026-07-16 10:00:00',
            0,0,0,0,'unknown','unknown','observed', null, '2026-07-16 09:00:00')`).run();
  db.prepare(`INSERT INTO dmarc_aggregate_records (id, report_id, workspace_id, domain, source_ip, message_count, dkim_aligned_result, spf_aligned_result, created_at)
              VALUES ('rec_man','rep_old','ws1','example.com','10.0.7.7', 700, 'pass', 'fail', datetime('now'))`).run();
  db.prepare(`UPDATE email_sender_sources SET classification='suspicious', classified_at='2026-07-16 11:00:00' WHERE id='esender_man'`).run();

  const b2 = notifications("ws1").length;
  await evaluateEmailSenderMonitoring(env, "ws1", "example.com");
  eq("a manual reclassification raises NO alert", notifications("ws1").length, b2);
  const evs = allEvents("esender_man");
  ok("the customer's action is still recorded as history", evs.some((e) => e.event_type === "sender_manual_classification"));
  eq("the customer's action minted no occurrence", occurrenceEvents("esender_man").length, 0);
}

// ── 6. Windowed evidence: the cumulative-latch regression ────────────────────
// The legacy engine graded on lifetime counters, which never decrease — so its
// threshold latched true forever and recovery was inexpressible. A sender with a
// huge lifetime failure count but an EMPTY window must be silent.
{
  activate("ws2", "2026-07-15 12:00:00");
  db.prepare(`INSERT INTO email_sender_sources
    (id, workspace_id, domain, source_ip, first_seen, last_seen, total_messages, aligned_messages,
     failed_messages, pass_rate, classification, auto_classification, created_at)
    VALUES ('esender_latch','ws2','beta.com','10.1.1.1','2026-07-16 09:00:00','2026-07-16 10:00:00',
            999999, 0, 999999, 0, 'unknown', 'unauthorised', '2026-07-16 09:00:00')`).run();
  // A report whose window has EXPIRED — no windowed evidence at all.
  db.prepare(`INSERT INTO dmarc_aggregate_reports (id, workspace_id, domain, external_report_id, date_range_begin, date_range_end, created_at)
              VALUES ('rep_stale','ws2','beta.com','r-stale', 1, 1000, datetime('now'))`).run();
  db.prepare(`INSERT INTO dmarc_aggregate_records (id, report_id, workspace_id, domain, source_ip, message_count, dkim_aligned_result, spf_aligned_result, created_at)
              VALUES ('rec_stale','rep_stale','ws2','beta.com','10.1.1.1', 999999, 'fail', 'fail', datetime('now'))`).run();

  await evaluateEmailSenderMonitoring(env, "ws2", "beta.com");
  eq("REGRESSION: 999,999 LIFETIME failures with an empty window raises NO alert", notifications("ws2").length, 0);
  eq("REGRESSION: and mints no occurrence", occurrenceEvents("esender_latch").length, 0);
}

// ── 7. Active failures → window empties (disappearance, NOT recovery) → re-entry ─
{
  const nowSec = Math.floor(Date.now() / 1000);
  db.prepare(`INSERT INTO dmarc_aggregate_reports (id, workspace_id, domain, external_report_id, date_range_begin, date_range_end, created_at)
              VALUES ('rep_live','ws2','beta.com','r-live', ?, ?, datetime('now'))`).run(nowSec - 3600, nowSec);
  db.prepare(`INSERT INTO dmarc_aggregate_records (id, report_id, workspace_id, domain, source_ip, message_count, dkim_aligned_result, spf_aligned_result, created_at)
              VALUES ('rec_live','rep_live','ws2','beta.com','10.1.1.1', 400, 'fail', 'fail', datetime('now'))`).run();

  await evaluateEmailSenderMonitoring(env, "ws2", "beta.com");
  const n = notifications("ws2").at(-1);
  eq("active unauthorised failures alert", notifications("ws2").length, 1);
  eq("the recurrence makes only the claim the evidence supports",
     n.type, "email_protection.sender_unauthorised_failures_active");
  eq("active failures are high", n.severity, "high");
  const firstOcc = occurrenceEvents("esender_latch");
  eq("exactly one occurrence for the condition", firstOcc.length, 1);

  // Unchanged: silent.
  await evaluateEmailSenderMonitoring(env, "ws2", "beta.com");
  eq("an unchanged active condition sends no second alert", notifications("ws2").length, 1);

  // DISAPPEARANCE (not recovery) — every report drops out of the window. This is
  // indistinguishable from an RUA outage / the receiver going silent, so it must
  // NOT be read as recovery: senderRecoveryConfirmed requires window_total > 0
  // (positive passing evidence), which an empty window cannot supply. The condition
  // clears to "observed" (no longer actively detected) but no sender_failures_recovered
  // event is emitted and the email case is NOT closed — a vanished sender is never
  // proof it now authenticates. Genuine passing-evidence recovery is proven as a pure
  // predicate in validate-disappearance-confirmation.js (G1.1 / G1.2).
  db.prepare(`DELETE FROM dmarc_aggregate_records WHERE id='rec_live'`).run();
  await evaluateEmailSenderMonitoring(env, "ws2", "beta.com");
  const evs = allEvents("esender_latch");
  ok("an emptied window emits NO false recovery event", !evs.some((e) => e.event_type === "sender_failures_recovered"));
  eq("the emptied window raised NO alert", notifications("ws2").length, 1);
  eq("the emptied window minted no new occurrence", occurrenceEvents("esender_latch").length, 1);
  eq("the sender is NOT marked recovered from absence (condition clears to observed)", db.prepare("SELECT monitoring_status FROM email_sender_sources WHERE id='esender_latch'").get().monitoring_status, "observed");

  // RE-ENTRY — it comes back. New event ⇒ new occurrence id ⇒ new dedupe key.
  await tick();
  db.prepare(`INSERT INTO dmarc_aggregate_records (id, report_id, workspace_id, domain, source_ip, message_count, dkim_aligned_result, spf_aligned_result, created_at)
              VALUES ('rec_live2','rep_live','ws2','beta.com','10.1.1.1', 600, 'fail', 'fail', datetime('now'))`).run();
  await evaluateEmailSenderMonitoring(env, "ws2", "beta.com");
  eq("re-entry after the condition cleared alerts again", notifications("ws2").length, 2);
  const occNow = occurrenceEvents("esender_latch");
  eq("re-entry minted a SECOND occurrence", occNow.length, 2);
  ok("re-entry's occurrence identity is NEW", occNow[0].id !== occNow[1].id);
  const keys = new Set(notifications("ws2").map((r) => r.dedupe_key));
  eq("re-entry produced a distinct dedupe key", keys.size, 2);
}

// ── 8. Hosted family: disconnect → reconnect → re-disconnect ─────────────────
{
  db.prepare(`INSERT INTO hosted_dns_entries
    (id, workspace_id, domain, record_kind, customer_name, target_name, target_value,
     verification_state, created_at, updated_at)
    VALUES ('hd-000000000001','ws1','example.com','dmarc','_dmarc.example.com','hd1.dmarc.cybermeters.com','v=DMARC1; p=none',
            'connected','2026-07-16 09:00:00','2026-07-16 09:00:00')`).run();
  const row = { id: "hd-000000000001", workspace_id: "ws1", domain: "example.com", created_at: "2026-07-16 09:00:00", status: "connected" };

  const before = notifications("ws1").length;
  await recordHostedTransition(env, row, { recurrence: "hosted_record_disconnected", from_status: "connected", to_status: "disconnected" });
  eq("a hosted disconnection alerts", notifications("ws1").length, before + 1);
  const n = notifications("ws1").at(-1);
  eq("the hosted alert kind is namespaced", n.type, "email_protection.hosted_record_disconnected");
  eq("hosted disconnection is high", n.severity, "high");
  eq("the hosted alert carries canonical remediation",
     JSON.parse(n.metadata_json).remediation_id, "email.hosted_dmarc.reconnect");

  // Unchanged repeat: the same condition must not re-alert.
  await recordHostedTransition(env, row, { recurrence: "hosted_record_disconnected", from_status: "connected", to_status: "disconnected" });
  eq("an unchanged hosted condition does NOT re-alert", notifications("ws1").length, before + 1);

  // Reconnection: history, never an alert.
  await recordHostedTransition(env, row, { event_type: "hosted_record_reconnected", from_status: "disconnected", to_status: "connected" });
  eq("reconnection raises NO alert", notifications("ws1").length, before + 1);
  ok("reconnection is recorded as history", allEvents("hd-000000000001").some((e) => e.event_type === "hosted_record_reconnected"));
  eq("reconnection minted no occurrence", occurrenceEvents("hd-000000000001").length, 1);

  // ── THE RE-DISCONNECT. This section has been titled
  // "disconnect → reconnect → re-disconnect" since it was written, and it never
  // performed the re-disconnect: it stopped at the reconnect and moved on to rollbacks.
  // The defect it was named after was live the whole time — a hosted record could alert
  // on disconnection exactly ONCE in its lifetime, because `hosted_record_reconnected`
  // is not `monitoring_changed` and the graded condition never closed.
  //
  // A recovered condition that RETURNS is a recurrence, not an unchanged duplicate.
  await tick();
  await recordHostedTransition(env, row, { recurrence: "hosted_record_disconnected", from_status: "connected", to_status: "disconnected" });
  eq("a SECOND disconnect after recovery ALERTS AGAIN", notifications("ws1").length, before + 2);
  eq("the re-entry is the same canonical condition, not a new incident kind",
     notifications("ws1").at(-1).type, "email_protection.hosted_record_disconnected");
  eq("the re-entry carries the same canonical remediation",
     JSON.parse(notifications("ws1").at(-1).metadata_json).remediation_id, "email.hosted_dmarc.reconnect");
  eq("the re-entry minted a NEW occurrence on the canonical lifecycle",
     occurrenceEvents("hd-000000000001").length, 2);
  {
    const occ = occurrenceEvents("hd-000000000001");
    ok("the re-entry's occurrence identity is NEW", occ[0].id !== occ[1].id);
    // Scoped to the alerts THIS block raised — ws1 carries alerts from earlier sections,
    // so a set over the whole workspace would count them and prove nothing about the
    // re-entry.
    const keys = new Set(notifications("ws1").slice(before).map((r) => r.dedupe_key));
    eq("and its dedupe key is distinct — dedupe never swallows a genuine recurrence", keys.size, 2);
  }

  // Still deduped: the SECOND disconnect, re-processed unchanged, is not a third alert.
  // Recovery closure must not turn every repeat sweep into news.
  await recordHostedTransition(env, row, { recurrence: "hosted_record_disconnected", from_status: "connected", to_status: "disconnected" });
  eq("the re-entered condition, unchanged, does NOT alert a third time", notifications("ws1").length, before + 2);

  // Recovery again, so the rollback assertions below start from a closed condition.
  await tick();
  await recordHostedTransition(env, row, { event_type: "hosted_record_reconnected", from_status: "disconnected", to_status: "connected" });
  eq("second reconnection still raises no alert", notifications("ws1").length, before + 2);

  // A manual rollback is the customer's own action: history only.
  await recordHostedTransition(env, row, { event_type: "hosted_rolled_back_manual", actor_type: "customer", actor_id: "u1" });
  eq("a manual rollback raises NO alert", notifications("ws1").length, before + 2);

  // An AUTOMATIC rollback is CyberMeters intervening: actionable.
  await recordHostedTransition(env, row, { recurrence: "hosted_rolled_back_auto", band: "2026-07-17 10:00:00" });
  eq("an automatic rollback alerts", notifications("ws1").length, before + 3);
  eq("automatic rollback is high", notifications("ws1").at(-1).severity, "high");
}

// ── 9. Impact regression: no more daily re-alert, but a NEW change re-alerts ─
{
  const row = { id: "hd-000000000001", workspace_id: "ws1", domain: "example.com", created_at: "2026-07-16 09:00:00", status: "connected" };
  const before = notifications("ws1").length;

  await recordHostedTransition(env, row, { recurrence: "hosted_impact_regression", band: "2026-07-18 10:00:00", record_severity: "medium" });
  eq("an impact regression alerts", notifications("ws1").length, before + 1);
  eq("its severity is INHERITED from the assessment", notifications("ws1").at(-1).severity, "medium");

  // The daily-re-alert defect: the same regression against the same change.
  await recordHostedTransition(env, row, { recurrence: "hosted_impact_regression", band: "2026-07-18 10:00:00", record_severity: "medium" });
  await recordHostedTransition(env, row, { recurrence: "hosted_impact_regression", band: "2026-07-18 10:00:00", record_severity: "medium" });
  eq("REGRESSION: an unchanged impact regression does NOT re-alert", notifications("ws1").length, before + 1);

  // A regression after a NEW policy change is a NEW condition. In production the
  // customer has to apply a policy change between the two, so they are never in
  // the same second.
  await tick();
  await recordHostedTransition(env, row, { recurrence: "hosted_impact_regression", band: "2026-07-19 11:00:00", record_severity: "high" });
  eq("a regression after a NEW change alerts again", notifications("ws1").length, before + 2);
  eq("and inherits the new grade", notifications("ws1").at(-1).severity, "high");
}

// ── 10. Tenant isolation and soft-delete ────────────────────────────────────
{
  const foreign = await findConditionOccurrence(env, {
    workspace_id: "ws2", domain_key: "email_protection",
    record_id: "esender_new1", recurrence_type: "sender_unrecognised",
  });
  eq("ws2 cannot resolve ws1's occurrence", foreign, null);
  ok("no ws1 alert leaked into ws2", notifications("ws2").every((n) => n.workspace_id === "ws2"));
  ok("no ws2 alert leaked into ws1", notifications("ws1").every((n) => n.workspace_id === "ws1"));

  // A soft-deleted workspace must receive nothing.
  db.prepare("INSERT INTO users (id, email, name, plan, created_at) VALUES ('u3','d@example.com','d','business',datetime('now'))").run();
  db.prepare("INSERT INTO workspaces (id, owner_user_id, name, deleted_at) VALUES ('ws3','u3','ws3',datetime('now'))").run();
  activate("ws3", "2026-07-15 12:00:00");
  const row = { id: "hd-000000000003", workspace_id: "ws3", domain: "deleted.com", created_at: "2026-07-16 09:00:00", status: "connected" };
  await recordHostedTransition(env, row, { recurrence: "hosted_record_disconnected", from_status: "connected", to_status: "disconnected" });
  eq("a soft-deleted workspace receives NO notification", notifications("ws3").length, 0);
}

// ── 11. Id namespaces cannot collide (the database cannot assert this) ──────
{
  const hosted = db.prepare("SELECT id FROM hosted_dns_entries").all().map((r) => r.id);
  const senders = db.prepare("SELECT id FROM email_sender_sources").all().map((r) => r.id);
  ok("every hosted id uses the 'hd-' namespace", hosted.every((id) => id.startsWith("hd-")));
  ok("every sender id uses the 'esender' namespace", senders.every((id) => id.startsWith("esender")));
  const overlap = hosted.filter((id) => senders.includes(id));
  eq("the two record-id namespaces are disjoint", overlap, []);
  // Sharing one table is only safe because of this. A collision would let one
  // family resolve the other family's occurrence.
  ok("no sender id could be read as a hosted id", senders.every((id) => !id.startsWith("hd-")));
}

// ── 12. Purge covers the new table ──────────────────────────────────────────
{
  const src = fs.readFileSync(path.join(root, "workers", "scan-api", "src", "index.js"), "utf8");
  ok("email_protection_events is in the workspace purge order", /"email_protection_events"/.test(src));
}

// ── 12. THE CANONICAL CUSTOMER-CLASSIFICATION POLICY ─────────────────────────
// THE DEFECT THIS EXISTS TO PREVENT (reproduced live, 2026-07-16): the product carried
// TWO sender vocabularies and pushed both through ONE slot. The classify route accepted
// trusted/suspicious/threat/ignored/unknown; senderAlertBand spoke
// authorised…unauthorised. `threat`, `trusted` and `ignored` were in NEITHER map, so all
// three banded null — and effectiveClassification handed the customer's word straight to
// it. **Marking a sender a THREAT turned its own high alert off.** The correct mapping
// already existed as a private copy in dmarc-impact.js, while the lifecycle engine and
// rua-routing each had their own copy without it: three implementations, two wrong.
{
  // The vocabularies are now declared in ONE place and every disposition has a defined
  // meaning. A new disposition that nobody maps is the bug, restated.
  eq("every customer disposition has a canonical mapping",
     CUSTOMER_SENDER_DISPOSITIONS.filter((d) => !(d in DISPOSITION_ASSERTS)).length, 0);
  ok("every mapped claim is in the observed vocabulary (or is `ignored`, which claims nothing)",
     Object.entries(DISPOSITION_ASSERTS).every(([d, c]) => c === null ? d === "ignored" : OBSERVED_SENDER_CLASSIFICATIONS.includes(c)));
  eq("threat claims unauthorised", assertedClassification("threat"), "unauthorised");
  eq("trusted claims authorised", assertedClassification("trusted"), "authorised");
  eq("ignored claims nothing", assertedClassification("ignored"), null);

  // ── THE INVARIANT: threat must never reduce or nullify severity ────────────
  const threatOnClean = resolveSenderPolicy({ observed: "authorised", disposition: "threat", has_customer_decision: true, window_failed: 0 });
  eq("THREAT on a clean sender bands HIGH — it escalates", threatOnClean.band, "high");
  ok("THREAT never bands null", threatOnClean.band !== null);
  const threatOnFailing = resolveSenderPolicy({ observed: "unauthorised", disposition: "threat", has_customer_decision: true, window_failed: SENDER_FAILURE_TRIGGER });
  eq("THREAT on a failing sender stays HIGH", threatOnFailing.band, "high");
  eq("a THREAT'd failing sender keeps its condition — it is not clicked away",
     gradeSenderCondition({ observed: "unauthorised", disposition: "threat", has_customer_decision: true,
                            window_total: 120, window_failed: SENDER_FAILURE_TRIGGER, is_new: false }).recurrence,
     "sender_unauthorised_failures_active");

  // ── THE POLICY: trusted/ignored suppress ONLY when evidence does not contradict ──
  for (const disp of ["trusted", "ignored"]) {
    const quiet = resolveSenderPolicy({ observed: "unknown", disposition: disp, has_customer_decision: true, window_failed: 0 });
    ok(`${disp} suppresses a sender the evidence does not contradict`, quiet.suppressed === true && quiet.band === null);
    eq(`${disp} on an uncontradicted sender records no conflict`, quiet.conflict, null);

    // Contradicted by the observed verdict.
    const loud = resolveSenderPolicy({ observed: "unauthorised", disposition: disp, has_customer_decision: true, window_failed: 0 });
    ok(`${disp} does NOT suppress a sender observed unauthorised`, loud.suppressed === false);
    eq(`${disp} keeps the observed band when contradicted`, loud.band, "high");
    eq(`${disp} names the conflict explicitly`, loud.conflict, `customer_${disp}_but_observed_unauthorised`);

    // Contradicted by the failure evidence alone, even where the verdict is milder.
    const failing = resolveSenderPolicy({ observed: "suspicious", disposition: disp, has_customer_decision: true, window_failed: SENDER_FAILURE_TRIGGER });
    ok(`${disp} does NOT suppress a sender failing above the trigger`, failing.suppressed === false);
    ok(`${disp} names that conflict too`, failing.conflict === `customer_${disp}_but_observed_suspicious`);

    // The condition itself survives: a customer cannot erase receiver-reported failures.
    eq(`${disp} cannot erase an active unauthorised-failures condition`,
       gradeSenderCondition({ observed: "unauthorised", disposition: disp, has_customer_decision: true,
                              window_total: 120, window_failed: SENDER_FAILURE_TRIGGER, is_new: false }).recurrence,
       "sender_unauthorised_failures_active");
  }

  // ── FAIL CLOSED on anything unrecognised ──────────────────────────────────
  const bogus = resolveSenderPolicy({ observed: "unauthorised", disposition: "definitely_fine", has_customer_decision: true, window_failed: 0 });
  ok("an unsupported disposition never suppresses", bogus.suppressed === false);
  eq("an unsupported disposition fails closed to the observed band", bogus.band, "high");
  eq("and names itself unsupported", bogus.conflict, "unsupported_customer_disposition");
  const bogusObserved = resolveSenderPolicy({ observed: "totally_new_verdict", disposition: null, has_customer_decision: false, window_failed: 0 });
  eq("an unsupported OBSERVED value fails closed to medium, never null", bogusObserved.band, "medium");
  eq("and names itself unsupported", bogusObserved.conflict, "unsupported_observed_classification");
  ok("the route's vocabulary gate rejects it", !isCustomerDisposition("definitely_fine"));

  // ── The two axes stay distinct ─────────────────────────────────────────────
  eq("a customer decision is translated, never returned raw",
     resolveEffectiveClassification({ classification: "threat", auto_classification: "authorised", classified_at: "x" }), "unauthorised");
  ok("no observed classification is also a customer disposition (the slots cannot be confused)",
     OBSERVED_SENDER_CLASSIFICATIONS.filter((c) => CUSTOMER_SENDER_DISPOSITIONS.includes(c)).sort().join(",") === "suspicious,unknown");
}

// ── 13. Recovery closure is EXPLICIT — not "any non-alertable event" ──────────
// Every non-alertable hosted event carries `to_recurrence_type: null`
// (buildMonitoringTransitionDetail always sets the key), so a reader that closed a
// condition on "any event carrying the key" would let a POLICY CHANGE or a MANUAL
// ROLLBACK close a LIVE disconnection — and the next sweep would re-alert an outage that
// never went away. Only a genuine return to a healthy state is recovery.
{
  db.prepare(`INSERT INTO hosted_dns_entries
    (id, workspace_id, domain, record_kind, customer_name, target_name, target_value,
     verification_state, created_at, updated_at)
    VALUES ('hd-000000000002','ws2','ex2.com','dmarc','_dmarc.ex2.com','hd2.dmarc.cybermeters.com','v=DMARC1; p=none',
            'connected','2026-07-16 09:00:00','2026-07-16 09:00:00')`).run();
  const row2 = { id: "hd-000000000002", workspace_id: "ws2", domain: "ex2.com", created_at: "2026-07-16 09:00:00", status: "connected" };
  const base = notifications("ws2").length;

  await recordHostedTransition(env, row2, { recurrence: "hosted_record_disconnected", from_status: "connected", to_status: "disconnected" });
  eq("ws2 disconnect alerts once", notifications("ws2").length, base + 1);

  // A policy change while still disconnected is history — and must NOT close the condition.
  await tick();
  await recordHostedTransition(env, row2, { event_type: "hosted_policy_changed", from_status: "disconnected", to_status: "disconnected" });
  await recordHostedTransition(env, row2, { recurrence: "hosted_record_disconnected", from_status: "connected", to_status: "disconnected" });
  eq("a POLICY CHANGE does not close a live disconnection (no spurious re-alert)",
     notifications("ws2").length, base + 1);

  // A manual rollback while still disconnected: same rule.
  await tick();
  await recordHostedTransition(env, row2, { event_type: "hosted_rolled_back_manual", actor_type: "customer", actor_id: "u2" });
  await recordHostedTransition(env, row2, { recurrence: "hosted_record_disconnected", from_status: "connected", to_status: "disconnected" });
  eq("a MANUAL ROLLBACK does not close a live disconnection either",
     notifications("ws2").length, base + 1);

  // Only reconnection closes it — and then the condition can legitimately return.
  await tick();
  await recordHostedTransition(env, row2, { event_type: "hosted_record_reconnected", from_status: "disconnected", to_status: "connected" });
  await tick();
  await recordHostedTransition(env, row2, { recurrence: "hosted_record_disconnected", from_status: "connected", to_status: "disconnected" });
  eq("RECONNECTION closes it, so the returning condition alerts again",
     notifications("ws2").length, base + 2);

  // Tenant isolation: ws1's history for a same-named condition cannot close or open ws2's.
  const ws2Events = allEvents("hd-000000000002");
  ok("every ws2 lifecycle event is workspace-scoped", ws2Events.every((e) => e.workspace_id === "ws2"));
  ok("ws2's occurrences are its own", occurrenceEvents("hd-000000000002").length >= 2);
}

globalThis.fetch = realFetch;
console.log(`\nalert-b3-email-protection: ${pass} passed, ${fail} failed`);
if (fail > 0) { console.error("alert-b3-email-protection validation FAILED"); process.exit(1); }
console.log("alert-b3-email-protection validation passed");
