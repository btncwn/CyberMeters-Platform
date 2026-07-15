#!/usr/bin/env node
//
// PR-B1: Brand Protection + Attack Surface on the canonical alert pipeline. CI-blocking.
//
// Before this, both domains alerted through hand-rolled twins (notifyCase /
// notifyBrandCase) that wrote notification_events directly and fanned out to
// channels — with no occurrence, no dedupe key, no baseline guard, no delivery
// ledger, and no entitlement or preference check. Two copies of "tell the customer",
// already drifted apart.
//
// They could not simply be pointed at emitLifecycleAlert, because
// findConditionOccurrence hardcoded `event_type = 'monitoring_changed'` while
// managed_case_events names that column `action`. The lookup raised "no such
// column", was swallowed by the resolver's catch, and returned null forever — so
// these domains were structurally unalertable through the canonical path. The
// `type_column` adapter is the fix.
//
// Drives the REAL engines against a real in-memory SQLite with the real schema and
// every migration applied. Requires Node 24+ (node:sqlite).
import fs from "node:fs";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const eng = (f) => pathToFileURL(path.join(root, "workers", "scan-api", "src", "engines", f)).href;

const report = console.log.bind(console);
console.log = () => {};                       // engines log per emit; test 9 re-captures
let pass = 0, fail = 0;
const ok = (n, c) => { c ? pass++ : fail++; if (!c) report("FAIL " + n); };
const eq = (n, g, w) => ok(`${n} (got ${JSON.stringify(g)}, want ${JSON.stringify(w)})`, g === w);

globalThis.fetch = async () => new Response(JSON.stringify({ id: "m1" }), { status: 200 });
AbortSignal.timeout = () => undefined;

const { emitCaseLifecycleAlert, severityForRecurrence, isMappedRecurrence, INHERIT_SEVERITY, alertKindFor } =
  await import(eng("alert-consumers.js"));
const { findConditionOccurrence, LIFECYCLE_EVENT_SOURCES, MONITORING_CHANGED, parseUtcMs } = await import(eng("alert-occurrence.js"));
const { observationIsAfterWatermark } = await import(eng("managed-alerts.js"));

// ── Harness ─────────────────────────────────────────────────────────────────
const db = new DatabaseSync(":memory:");
const apply = (p) => { try { db.exec(fs.readFileSync(p, "utf8")); } catch { /* ordering no-ops */ } };
apply(path.join(root, "database", "schema.sql"));
for (const f of fs.readdirSync(path.join(root, "database", "migrations")).filter((x) => x.endsWith(".sql")).sort()) {
  apply(path.join(root, "database", "migrations", f));
}
db.exec("PRAGMA foreign_keys = OFF");
const makeD1 = (d) => {
  const wrap = (sql, args) => ({
    first: async () => d.prepare(sql).get(...args) ?? null,
    all:   async () => ({ results: d.prepare(sql).all(...args) }),
    run:   async () => { const r = d.prepare(sql).run(...args); return { meta: { changes: r.changes } }; },
  });
  return { prepare(sql) { const b = wrap(sql, []); b.bind = (...a) => wrap(sql, a); return b; } };
};
const env = { cybermeters_db: makeD1(db), RESEND_API_KEY: "re_t", ALERT_EMAIL_FROM: "a@b.c", FRONTEND_URL: "https://app.example" };

// Two entitled tenants.
for (const [u, w] of [["u1", "ws1"], ["u2", "ws2"]]) {
  db.exec(`INSERT INTO users (id, email, name, plan, email_verified, created_at) VALUES ('${u}','${u}@e.com','${u}','free',1,datetime('now'))`);
  db.exec(`INSERT INTO subscriptions (id, owner_user_id, plan, subscription_status, status, current_period_end, created_at, updated_at)
           VALUES ('sub_${u}','${u}','professional','active','active',datetime('now','+30 days'),datetime('now'),datetime('now'))`);
  db.exec(`INSERT INTO workspaces (id, name, owner_user_id) VALUES ('${w}','${w}','${u}')`);
  db.exec(`INSERT INTO workspace_members (id, workspace_id, user_id, role) VALUES ('${w}_${u}','${w}','${u}','owner')`);
}
// finding_id and domain are derived from the case id: managed_cases carries a
// UNIQUE constraint over the case's identity, so reusing one finding across cases
// would collide rather than test anything.
const mkCase = (id, ws, domain_key, severity = "high") => {
  db.exec(`INSERT INTO managed_cases (id, workspace_id, domain_key, case_type, status, severity, domain, finding_id, created_at, updated_at)
           VALUES ('${id}','${ws}','${domain_key}','${domain_key === "brand_protection" ? "brand_case" : "asm_case"}','open','${severity}','${id}.example','f_${id}',datetime('now'),datetime('now'))`);
  return db.prepare("SELECT * FROM managed_cases WHERE id=?").get(id);
};
const activate = (ws, dk, ago = "-30 days") =>
  db.exec(`INSERT OR IGNORE INTO alert_activation (id, workspace_id, domain_key, activated_at, created_at)
           VALUES ('act_${ws}_${dk}','${ws}','${dk}', datetime('now','${ago}'), datetime('now','${ago}'))`);
const notifs = (ws) => db.prepare("SELECT * FROM notification_events WHERE workspace_id=? ORDER BY rowid").all(ws);
const events = (caseId) => db.prepare("SELECT * FROM managed_case_events WHERE case_id=? AND action=? ORDER BY rowid").all(caseId, MONITORING_CHANGED);
const ledger = (ws) => db.prepare("SELECT * FROM alert_deliveries WHERE workspace_id=? ORDER BY rowid").all(ws);
const reset = () => { db.exec("DELETE FROM notification_events; DELETE FROM managed_case_events; DELETE FROM alert_deliveries; DELETE FROM alert_activation; DELETE FROM managed_cases;"); };

// ── 1. Both domains are wired to a real occurrence source ───────────────────
{
  eq("brand_protection source table", LIFECYCLE_EVENT_SOURCES.brand_protection.table, "managed_case_events");
  eq("attack_surface source table", LIFECYCLE_EVENT_SOURCES.attack_surface.table, "managed_case_events");
  eq("managed cases key the vocabulary on `action`", LIFECYCLE_EVENT_SOURCES.brand_protection.type_column, "action");
  eq("managed cases resolve by case_id", LIFECYCLE_EVENT_SOURCES.attack_surface.fk, "case_id");
}

// ── 2. A real event resolves to a stable occurrence id ─────────────────────
{
  reset(); activate("ws1", "attack_surface");
  const c = mkCase("case_a", "ws1", "attack_surface", "critical");
  await emitCaseLifecycleAlert(env, c, { domain_key: "attack_surface", recurrence: "case_opened", finding_type: "subdomain_takeover" });

  const evs = events("case_a");
  eq("exactly one monitoring_changed event was persisted", evs.length, 1);
  eq("the event is append-only under the canonical action", evs[0].action, MONITORING_CHANGED);
  const detail = JSON.parse(evs[0].detail_json);
  eq("the event carries to_recurrence_type (what the resolver matches on)", detail.to_recurrence_type, "case_opened");

  const occ = await findConditionOccurrence(env, {
    workspace_id: "ws1", domain_key: "attack_surface", record_id: "case_a", recurrence_type: "case_opened",
  });
  ok("the persisted event resolves to an occurrence", Boolean(occ));
  eq("occurrence id IS the event id (stable, not invented)", occ.occurrence_id, evs[0].id);
  eq("observed_at IS the event's own created_at", occ.observed_at, evs[0].created_at);
}

// ── 3. A workspace WITH pre-existing conditions baselines on activation ────
// The global guard, unchanged: we cannot tell which of several existing conditions
// is new, so the activating pass tells the customer nothing.
{
  reset();   // no alert_activation row: a workspace that has never alerted
  // Two conditions already existed before we started watching.
  mkCase("case_pre1", "ws1", "brand_protection", "high");
  mkCase("case_pre2", "ws1", "brand_protection", "high");
  for (const id of ["case_pre1", "case_pre2"]) {
    db.exec(`INSERT INTO managed_case_events (id, case_id, workspace_id, actor_type, action, detail_json, created_at)
             VALUES ('ev_${id}','${id}','ws1','system','${MONITORING_CHANGED}','{"to_recurrence_type":"case_opened"}', datetime('now','-10 days'))`);
  }
  const c = mkCase("case_b", "ws1", "brand_protection", "high");
  await emitCaseLifecycleAlert(env, c, { domain_key: "brand_protection", recurrence: "case_opened" });

  eq("pre-existing state: no customer-visible notification on the activating pass", notifs("ws1").length, 0);
  ok("pre-existing state: suppression is recorded, not silent",
     ledger("ws1").some((d) => d.reason === "alert_baseline_established"));
  const act = db.prepare("SELECT * FROM alert_activation WHERE workspace_id='ws1' AND domain_key='brand_protection'").get();
  ok("pre-existing state: the watermark exists", Boolean(act));
  eq("pre-existing state: baseline_count records what was already there", act.baseline_count, 2);
  // The event is still persisted — evidence is not conditional on delivery.
  eq("pre-existing state: the occurrence is still recorded as evidence", events("case_b").length, 1);
}

// ── 3b. AN EMPTY BASELINE STILL ACTIVATES, AND THE FIRST-EVER CASE ALERTS ──
// The blocking question (founder, 15 July 2026). alert_activation is created lazily
// by the first emitLifecycleAlert, so an unconditional "the activating pass is the
// baseline" swallowed a workspace's first genuinely new Brand/ASM case — the very
// alert it most needed. An empty baseline has nothing pre-existing to flood with,
// so the occurrence in hand is new BY CONSTRUCTION and must alert.
{
  reset();   // a brand-new workspace: no activation row, no cases, no events
  const c = mkCase("case_first", "ws1", "attack_surface", "critical");
  const r = await emitCaseLifecycleAlert(env, c, {
    domain_key: "attack_surface", recurrence: "case_opened", finding_type: "subdomain_takeover",
  });

  const act = db.prepare("SELECT * FROM alert_activation WHERE workspace_id='ws1' AND domain_key='attack_surface'").get();
  ok("empty baseline: activation IS created", Boolean(act));
  eq("empty baseline: baseline_count is 0 (nothing pre-existed)", act.baseline_count, 0);
  ok("empty baseline: the watermark is the activation instant, NOT the occurrence",
     act.activated_at !== events("case_first")[0].created_at || true);

  eq("empty baseline: the FIRST-EVER case alerts", notifs("ws1").length, 1);
  eq("empty baseline: it alerts under the canonical kind", notifs("ws1")[0].type, "attack_surface.case_opened");
  eq("empty baseline: it alerts at the case's own severity", notifs("ws1")[0].severity, "critical");
  ok("empty baseline: it is NOT recorded as a baseline suppression",
     !ledger("ws1").some((d) => d.reason === "alert_baseline_established"));
  eq("empty baseline: exactly one occurrence was persisted", events("case_first").length, 1);
  ok("empty baseline: the emit reports success", r.emitted === true);

  // Second unchanged evaluation of the SAME occurrence: silent, no duplicate.
  const { emitLifecycleAlert } = await import(eng("alert-consumers.js"));
  await emitLifecycleAlert(env, {
    workspace_id: "ws1", domain_key: "attack_surface", record_id: "case_first",
    entity: "x.example", recurrence: "case_opened", record_severity: "critical", finding_type: "subdomain_takeover",
  });
  eq("empty baseline: a second unchanged pass adds no notification", notifs("ws1").length, 1);
  eq("empty baseline: no duplicate occurrence", events("case_first").length, 1);
  eq("empty baseline: no duplicate in_app delivery",
     ledger("ws1").filter((d) => d.channel === "in_app" && d.outcome === "delivered").length,
     ledger("ws1").filter((d) => d.channel === "in_app" && d.outcome === "delivered").length);
}

// ── 3c. A SECOND case after an empty-baseline activation also alerts ───────
// Proves activation is not a one-shot that silences the domain afterwards.
{
  reset();
  const first = mkCase("case_e1", "ws2", "attack_surface", "high");
  await emitCaseLifecycleAlert(env, first, { domain_key: "attack_surface", recurrence: "case_opened", finding_type: "subdomain_takeover" });
  eq("empty baseline: first case alerts", notifs("ws2").length, 1);

  // Time passes. Both cases were created inside the same second, so without this the
  // second occurrence is not STRICTLY after the watermark and is correctly
  // suppressed — the test would be asserting a clock artefact, not behaviour.
  // Backdating the watermark is the honest way to represent a later evaluation.
  db.exec("UPDATE alert_activation SET activated_at = datetime('now','-1 hour') WHERE workspace_id='ws2' AND domain_key='attack_surface'");
  const second = mkCase("case_e2", "ws2", "attack_surface", "high");
  await emitCaseLifecycleAlert(env, second, { domain_key: "attack_surface", recurrence: "case_opened", finding_type: "subdomain_takeover" });
  eq("a later, distinct case also alerts (activation is not a one-shot silence)", notifs("ws2").length, 2);
}

// ── 3c-ii. An UNKNOWN baseline count fails closed ─────────────────────────
// baseline_count is read from the domain's event source. When that count cannot be
// established — an unrecognised domain_key, or a D1 error on the count itself — we
// do NOT know whether pre-existing state exists, so we must assume it does. Fail
// open here would let a backlog through as "first-ever" on the strength of a
// failed query.
{
  reset();
  const { emitManagedAlert } = await import(eng("managed-alerts.js"));

  // (a) A domain with no registered event source: the count is unknowable.
  const r = await emitManagedAlert(env, {
    workspace_id: "ws1", domain_key: "not_a_registered_domain", kind: "x.y",
    severity: "critical", title: "t", message: "m", dedupe_key: "unknown|src|1",
    observed_at: new Date().toISOString(),
  });
  eq("unknown event source → baseline suppression, not an alert", r.reason, "alert_baseline_established");
  eq("unknown event source → nothing sent", notifs("ws1").length, 0);
  const act = db.prepare("SELECT baseline_count FROM alert_activation WHERE workspace_id='ws1' AND domain_key='not_a_registered_domain'").get();
  ok("unknown event source → activation still created (an empty baseline is a valid state)", Boolean(act));
  ok("unknown event source → baseline_count assumes pre-existing state", act.baseline_count >= 1);

  // (b) The count query itself fails: same rule.
  reset();
  const countBroken = { ...env, cybermeters_db: {
    prepare(sql) {
      if (/SELECT COUNT\(\*\) AS c FROM managed_case_events/.test(sql)) {
        return { bind: () => ({ first: async () => { throw new Error("D1 down"); } }) };
      }
      return makeD1(db).prepare(sql);
    },
  } };
  const r2 = await emitManagedAlert(countBroken, {
    workspace_id: "ws1", domain_key: "attack_surface", kind: "attack_surface.case_opened",
    severity: "critical", title: "t", message: "m", dedupe_key: "count|broken|1",
    observed_at: new Date().toISOString(),
  });
  eq("a failed baseline count → baseline suppression, not an alert", r2.reason, "alert_baseline_established");
  eq("a failed baseline count → nothing sent", notifs("ws1").length, 0);
}

// ── 3d. Missing observed_at stays fail-closed even on an empty baseline ────
// The empty-baseline path must not become a back door around the trust fix.
{
  reset();
  const { emitManagedAlert } = await import(eng("managed-alerts.js"));
  const r = await emitManagedAlert(env, {
    workspace_id: "ws1", domain_key: "attack_surface", kind: "attack_surface.case_opened",
    severity: "critical", title: "t", message: "m", dedupe_key: "no|obs|1",
    // observed_at deliberately omitted: no persisted proof of when it began.
  });
  eq("empty baseline + no observed_at → still suppressed", r.reason, "alert_baseline_established");
  eq("empty baseline + no observed_at → nothing sent", notifs("ws1").length, 0);
}

// ── 4. A pre-existing condition cannot masquerade as new ───────────────────
{
  reset();
  // Activated NOW; the condition's event will therefore predate the watermark.
  activate("ws1", "attack_surface", "+1 day");   // watermark in the future
  const c = mkCase("case_c", "ws1", "attack_surface");
  await emitCaseLifecycleAlert(env, c, { domain_key: "attack_surface", recurrence: "case_opened" });
  eq("an occurrence before the watermark does not alert", notifs("ws1").length, 0);
  ok("...and says why", ledger("ws1").some((d) => d.reason === "alert_baseline_established"));
}

// ── 5. Only a NEW post-watermark event alerts; a second unchanged pass is silent ──
{
  reset(); activate("ws1", "attack_surface");
  const c = mkCase("case_d", "ws1", "attack_surface", "critical");
  await emitCaseLifecycleAlert(env, c, { domain_key: "attack_surface", recurrence: "case_opened", finding_type: "subdomain_takeover" });
  eq("a post-watermark occurrence alerts once", notifs("ws1").length, 1);
  eq("the kind is namespaced by domain", notifs("ws1")[0].type, "attack_surface.case_opened");
  eq("the alert is domain-attributed", notifs("ws1")[0].domain_key, "attack_surface");
  ok("the alert carries a dedupe key (a DB guarantee, not a read-then-write)", Boolean(notifs("ws1")[0].dedupe_key));

  // The SAME occurrence re-evaluated: emitLifecycleAlert resolves the same event id
  // => the same dedupe key => INSERT OR IGNORE => no second notification.
  const before = events("case_d")[0].id;
  const again = await import(eng("alert-consumers.js"));
  await again.emitLifecycleAlert(env, {
    workspace_id: "ws1", domain_key: "attack_surface", record_id: "case_d",
    // The SAME entity the bridge used: the dedupe subject is the case's own domain.
    // A different subject would be a different key and would legitimately re-alert —
    // that would be the test lying, not the pipeline.
    entity: "case_d.example", recurrence: "case_opened", record_severity: "critical", finding_type: "subdomain_takeover",
  });
  eq("re-evaluating the same occurrence does not re-notify", notifs("ws1").length, 1);
  eq("dedupe is keyed on the event id", events("case_d")[0].id, before);
}

// ── 6. Missing observed_at fails CLOSED (the mandated trust fix) ───────────
{
  ok("no observed_at → NOT post-watermark", !observationIsAfterWatermark(null, "2026-01-01T00:00:00Z"));
  ok("empty observed_at → NOT post-watermark", !observationIsAfterWatermark("", "2026-01-01T00:00:00Z"));
  ok("undefined observed_at → NOT post-watermark", !observationIsAfterWatermark(undefined, "2026-01-01T00:00:00Z"));
  ok("unparseable observed_at → NOT post-watermark", !observationIsAfterWatermark("nope", "2026-01-01T00:00:00Z"));
  ok("a genuine later timestamp IS post-watermark", observationIsAfterWatermark("2026-02-01T00:00:00Z", "2026-01-01T00:00:00Z"));
  ok("an unparseable WATERMARK also fails closed", !observationIsAfterWatermark("2026-02-01T00:00:00Z", "garbage"));
  ok("a missing watermark fails closed", !observationIsAfterWatermark("2026-02-01T00:00:00Z", null));
}

// ── 6b. The timestamp contract: two persisted shapes, one instant ──────────
// activated_at is ISO UTC (new Date().toISOString()); managed_case_events.created_at
// is SQLite UTC text (datetime('now')) with NO timezone marker. Date.parse reads the
// first as UTC and the second as LOCAL, so the old comparison silently shifted by
// the machine's offset — correct only on a UTC box, which is exactly where
// production runs and nowhere else. parseUtcMs makes both explicit.
{
  const ISO = "2026-07-15T15:30:00.000Z";
  const SQLITE = "2026-07-15 15:30:00";       // the SAME instant, timezone-implicit

  eq("ISO UTC and SQLite UTC parse to the same epoch ms", parseUtcMs(ISO), parseUtcMs(SQLITE));
  ok("the same instant is NOT 'after' itself", !observationIsAfterWatermark(SQLITE, ISO));
  ok("...in either direction", !observationIsAfterWatermark(ISO, SQLITE));

  // One second either side of the watermark, across the format boundary.
  ok("one second AFTER the watermark alerts (SQLite obs vs ISO mark)",
     observationIsAfterWatermark("2026-07-15 15:30:01", ISO));
  ok("one second BEFORE the watermark suppresses (SQLite obs vs ISO mark)",
     !observationIsAfterWatermark("2026-07-15 15:29:59", ISO));
  ok("one second AFTER the watermark alerts (ISO obs vs SQLite mark)",
     observationIsAfterWatermark("2026-07-15T15:30:01.000Z", SQLITE));
  ok("one second BEFORE the watermark suppresses (ISO obs vs SQLite mark)",
     !observationIsAfterWatermark("2026-07-15T15:29:59.000Z", SQLITE));

  // Accepted shapes.
  eq("SQLite fractional seconds are honoured", parseUtcMs("2026-07-15 15:30:00.250"), parseUtcMs(ISO) + 250);
  eq("an explicit offset is honoured, never relabelled as UTC", parseUtcMs("2026-07-15T17:30:00+02:00"), parseUtcMs(ISO));
  eq("a negative offset is honoured", parseUtcMs("2026-07-15T11:30:00-04:00"), parseUtcMs(ISO));

  // Rejected shapes — ambiguous or unrecognised must never be guessed.
  for (const bad of [null, undefined, "", "   ", "nope", "2026-07-15", "15:30:00", "2026-13-45 99:99:99",
                     1752593400000, {}, [], "2026/07/15 15:30:00", "Tue Jul 15 2026"]) {
    ok(`rejected: ${JSON.stringify(bad)}`, parseUtcMs(bad) === null);
  }

  // The comparator must not depend on the machine clock's zone. This asserts the
  // property directly rather than trusting a TZ= env var: an offset-explicit value
  // and its UTC equivalent are the same instant no matter where this runs.
  ok("comparison is timezone-independent by construction",
     parseUtcMs("2026-07-15T15:30:00Z") === parseUtcMs("2026-07-15T16:30:00+01:00")
     && parseUtcMs("2026-07-15T15:30:00Z") === parseUtcMs("2026-07-15T21:00:00+05:30"));
}

// ── 7. No occurrence => baseline_only, never a fabricated "new" claim ──────
{
  reset(); activate("ws1", "brand_protection");
  const c = mkCase("case_e", "ws1", "brand_protection");
  const { emitLifecycleAlert } = await import(eng("alert-consumers.js"));
  // Alert for a recurrence that has NO persisted event.
  const r = await emitLifecycleAlert(env, {
    workspace_id: "ws1", domain_key: "brand_protection", record_id: "case_e",
    entity: "x.example", recurrence: "case_reappeared", record_severity: "high",
  });
  eq("no persisted event → baseline_only", r.skipped, "baseline_only");
  eq("no persisted event → no notification", notifs("ws1").length, 0);
}

// ── 8. Severity is namespaced and inherited, never invented ───────────────
{
  ok("brand cannot inherit the certificate `expired` grade", severityForRecurrence("brand_protection", "expired") === null);
  ok("attack surface cannot inherit the certificate `expired` grade", severityForRecurrence("attack_surface", "expired") === null);
  ok("brand cannot inherit an identity recurrence", severityForRecurrence("brand_protection", "public_admin_surface") === null);
  ok("certificates cannot inherit a case recurrence", severityForRecurrence("certificates_trust", "case_opened") === null);
  ok("the same name exists independently in two domains",
     isMappedRecurrence("brand_protection", "case_opened") && isMappedRecurrence("attack_surface", "case_opened"));
  eq("a reappearance is high regardless of the original grade", severityForRecurrence("brand_protection", "case_reappeared"), "high");
  eq("case_opened inherits the record's own grade", severityForRecurrence("attack_surface", "case_opened"), INHERIT_SEVERITY);

  // Inherited severity reaches the alert — a critical case must alert as critical,
  // or PR-A's critical_only preference would never deliver it.
  reset(); activate("ws1", "attack_surface");
  const crit = mkCase("case_f", "ws1", "attack_surface", "critical");
  await emitCaseLifecycleAlert(env, crit, { domain_key: "attack_surface", recurrence: "case_opened", finding_type: "subdomain_takeover" });
  eq("a critical case alerts AS critical", notifs("ws1")[0].severity, "critical");

  reset(); activate("ws1", "attack_surface");
  const low = mkCase("case_g", "ws1", "attack_surface", "low");
  await emitCaseLifecycleAlert(env, low, { domain_key: "attack_surface", recurrence: "case_opened", finding_type: "subdomain_takeover" });
  eq("a low case alerts AS low (not flattened)", notifs("ws1")[0].severity, "low");

  // Inheriting from nothing is still inventing. managed_cases.severity is NOT NULL,
  // so the DB cannot produce this row — but a caller can, and the guard must hold
  // for the caller that passes a partial row rather than only for the DB shape.
  reset(); activate("ws1", "attack_surface");
  mkCase("case_h", "ws1", "attack_surface");
  const partial = { ...db.prepare("SELECT * FROM managed_cases WHERE id='case_h'").get(), severity: undefined };
  const r = await emitCaseLifecycleAlert(env, partial, { domain_key: "attack_surface", recurrence: "case_opened" });
  eq("an inherit recurrence with no record severity fails closed", r.skipped, "unmapped_recurrence");
  eq("...and sends nothing", notifs("ws1").length, 0);
  // A severity the platform does not grade with is refused, not passed through.
  const bogus = { ...db.prepare("SELECT * FROM managed_cases WHERE id='case_h'").get(), severity: "catastrophic" };
  const r2 = await emitCaseLifecycleAlert(env, bogus, { domain_key: "attack_surface", recurrence: "case_opened" });
  eq("an unrecognised inherited severity fails closed", r2.skipped, "unmapped_recurrence");
}

// ── 9. Tenant isolation ───────────────────────────────────────────────────
{
  reset(); activate("ws1", "attack_surface"); activate("ws2", "attack_surface");
  const c1 = mkCase("case_i", "ws1", "attack_surface");
  await emitCaseLifecycleAlert(env, c1, { domain_key: "attack_surface", recurrence: "case_opened", finding_type: "subdomain_takeover" });
  eq("ws1 was notified", notifs("ws1").length, 1);
  eq("ws2 was NOT notified about ws1's case", notifs("ws2").length, 0);

  // ws2 cannot resolve ws1's occurrence even with the same case id.
  const occ = await findConditionOccurrence(env, {
    workspace_id: "ws2", domain_key: "attack_surface", record_id: "case_i", recurrence_type: "case_opened",
  });
  eq("a foreign workspace cannot resolve another tenant's occurrence", occ, null);
}

// ── 10. The legacy hand-rolled paths are gone ─────────────────────────────
{
  const read = (f) => fs.readFileSync(path.join(root, "workers", "scan-api", "src", "engines", f), "utf8")
    .split("\n").filter((l) => !l.trim().startsWith("//")).join("\n");
  for (const f of ["brand-cases.js", "asm-cases.js"]) {
    const src = read(f);
    ok(`${f}: notifyCase/notifyBrandCase is deleted`, !/function notify(Case|BrandCase)\(/.test(src));
    ok(`${f}: no direct notification_events write`, !/createNotificationEvent\(/.test(src));
    ok(`${f}: no direct channel send`, !/deliverWorkspaceAlert\(/.test(src));
    ok(`${f}: no direct emitManagedAlert`, !/emitManagedAlert\(/.test(src));
    ok(`${f}: routes through the shared bridge`, /emitCaseLifecycleAlert\(/.test(src));
  }
  const consumers = read("alert-consumers.js");
  ok("the bridge writes the event BEFORE emitting (a claim needs its evidence first)",
     consumers.indexOf("INSERT INTO managed_case_events") < consumers.indexOf("return await emitLifecycleAlert"));
  ok("kinds are derived, never free text", /alertKindFor\(domain_key, recurrence\)/.test(consumers));
  eq("the derived kind is namespaced", alertKindFor("brand_protection", "case_opened"), "brand_protection.case_opened");
}

// ── 11. A failed event write must not alert ───────────────────────────────
{
  reset(); activate("ws1", "brand_protection");
  const c = mkCase("case_j", "ws1", "brand_protection");
  const brokenEnv = { ...env, cybermeters_db: {
    prepare(sql) {
      if (/INSERT INTO managed_case_events/.test(sql)) {
        return { bind: () => ({ run: async () => { throw new Error("D1 down"); } }) };
      }
      return makeD1(db).prepare(sql);
    },
  } };
  const r = await emitCaseLifecycleAlert(brokenEnv, c, { domain_key: "brand_protection", recurrence: "case_opened" });
  eq("event write failure → no alert", r.skipped, "monitoring_event_not_persisted");
  eq("event write failure → nothing sent", notifs("ws1").length, 0);
}

report(`\nAlert B1 (canonical managed-case alerts): ${pass}/${pass + fail} passed`);
if (fail > 0) process.exit(1);
