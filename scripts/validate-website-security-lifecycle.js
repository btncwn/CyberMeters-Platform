#!/usr/bin/env node
//
// Website Security managed lifecycle + canonical alerts — mutation-tested, CI-blocking.
//
// Website Security always had the evidence (headers/ssl/tech), stable canonical
// finding ids, immutable R2 reports and nine canonical remediations. What it lacked
// was a row saying WHEN a condition began, so nothing could be shown to be new.
// This suite proves the row is honest.
//
// Every assertion drives the REAL evaluator against the REAL schema. The findings it
// is fed are the shape scoring.js actually emits (canonical slug ids), because the
// whole point of the engine is that D1's findings INSERT drops that slug.
//
// The properties that matter, in order of how badly they would hurt a customer:
//   1. a 14-month-old backlog does NOT alert on the day this ships (flood guard)
//   2. an unreachable site is NOT a recovery ("you fixed it!" because a probe timed out)
//   3. an unchanged rescan is silent
//   4. a genuine new condition alerts EXACTLY once
//   5. worsening escalates exactly once
//   6. reappearance after a verified recovery mints a NEW occurrence
//   7. rule/version churn does not become a customer event
//   8. tenants never cross
//
// Node 24+.
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const srcPath = (...p) => path.join(root, "workers", "scan-api", "src", ...p);
const eng = (f) => pathToFileURL(srcPath("engines", f)).href;

const {
  evaluateWebsiteSecurityForScan, websiteConditionSpec, WEBSITE_SECURITY_DOMAIN_KEY,
  WS_NON_ALERTABLE_EVENT_TYPES, WS_EVENT_DOMAIN_BASELINE, WS_EVENT_BASELINE,
  WS_EVENT_RESOLVED, WS_EVENT_UNKNOWN, listWebsiteSecurityConditions,
} = await import(eng("website-security-lifecycle.js"));
const { findConditionOccurrence, LIFECYCLE_EVENT_SOURCES, MONITORING_CHANGED } = await import(eng("alert-occurrence.js"));
const { severityForRecurrence, INHERIT_SEVERITY } = await import(eng("alert-consumers.js"));
const { resolveRemediation } = await import(eng("remediation-registry.js"));
const { buildScanQuality } = await import(eng("scan-engine.js"));

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
const realFetch = globalThis.fetch;
globalThis.fetch = async (url) => (String(url).includes("resend.com")
  ? new Response(JSON.stringify({ id: "email_1" }), { status: 200, headers: { "content-type": "application/json" } })
  : new Response("{}", { status: 200 }));

// An entitled, live workspace with a verified recipient — otherwise every alert stops
// at a gate and the suite would "pass" while proving nothing.
db.prepare("INSERT INTO users (id, email, name, plan, created_at) VALUES ('u1','o@example.com','o','professional',datetime('now'))").run();
db.prepare("UPDATE users SET email_verified = 1 WHERE id = 'u1'").run();
db.prepare(`INSERT INTO subscriptions (id, owner_user_id, plan, subscription_status, status, current_period_end, created_at, updated_at)
            VALUES ('s1','u1','professional','active','active',datetime('now','+30 days'),datetime('now'),datetime('now'))`).run();
db.prepare("INSERT INTO workspaces (id, owner_user_id, name) VALUES ('ws1','u1','Acme')").run();
db.prepare("INSERT INTO workspace_members (id, workspace_id, user_id, role) VALUES ('m1','ws1','u1','owner')").run();
db.prepare("INSERT INTO workspaces (id, owner_user_id, name) VALUES ('ws2','u1','Other')").run();
db.prepare("INSERT INTO workspace_members (id, workspace_id, user_id, role) VALUES ('m2','ws2','u1','owner')").run();
db.prepare("INSERT INTO workspaces (id, owner_user_id, name) VALUES ('wsDead','u1','Dead')").run();
db.prepare("UPDATE workspaces SET deleted_at = datetime('now') WHERE id = 'wsDead'").run();

const env = {
  cybermeters_db: makeD1(db),
  ALERT_EMAIL_FROM: "alerts@cybermeters.com",
  RESEND_API_KEY: "re_test",
  FRONTEND_URL: "https://app.cybermeters.com",
};

// Force the activation watermark to a known PAST instant, exactly as
// validate-alert-occurrence.js and validate-alert-b3-email-protection.js do.
// emitManagedAlert gates on `observed_at > activated_at` with a STRICT `>`, and both
// are stamped by SQLite datetime('now') at second precision — so a suite that fires a
// condition and its escalation milliseconds apart has them land in the same second as
// the watermark and be correctly suppressed as baseline. Production scans are hours
// apart. Pre-setting the watermark models that deterministically, without a sleep.
function activate(ws, at) {
  db.prepare(`INSERT OR IGNORE INTO alert_activation (id, workspace_id, domain_key, activated_at, baseline_count, created_at)
              VALUES (?, ?, 'website_security', ?, 0, datetime('now'))`).run(`act_${ws}`, ws, at);
}

const notifs = (ws) => db.prepare("SELECT * FROM notification_events WHERE workspace_id=?").all(ws);
const conds = (ws) => db.prepare("SELECT * FROM website_security_conditions WHERE workspace_id=?").all(ws);
const condFor = (ws, key) => db.prepare("SELECT * FROM website_security_conditions WHERE workspace_id=? AND condition_key=?").get(ws, key);
const allEvents = (recId) => db.prepare("SELECT * FROM website_security_events WHERE record_id=? ORDER BY created_at, rowid").all(recId);
// Occurrence-shaped events ONLY: `monitoring_changed` carrying to_recurrence_type.
const occurrences = (recId) => allEvents(recId)
  .filter((e) => e.event_type === MONITORING_CHANGED)
  .filter((e) => { try { return JSON.parse(e.detail_json || "{}").to_recurrence_type != null; } catch { return false; } });

// The findings scoring.js really emits, by canonical slug.
const F = {
  hstsMissing:   (sev = "high")   => ({ id: "header_missing_strict_transport_security", module: "headers", severity: sev, title: "Missing HSTS Header" }),
  hstsUncertain: ()               => ({ id: "header_missing_strict_transport_security", module: "headers", severity: "info", title: "HSTS — Validation Uncertain" }),
  noHttps:       ()               => ({ id: "ssl_not_available", module: "ssl", severity: "critical", title: "HTTPS Not Available" }),
  noRedirect:    (sev = "medium") => ({ id: "ssl_no_http_redirect", module: "ssl", severity: sev, title: "HTTP Does Not Redirect to HTTPS" }),
  malformedCsp:  ()               => ({ id: "header_malformed_content_security_policy", module: "headers", severity: "medium", title: "Malformed CSP Header" }),
  // Non-material Website Security findings: real, but never customer events.
  weakHsts:      ()               => ({ id: "header_weak_hsts", module: "headers", severity: "info", title: "Weak HSTS Configuration" }),
  techVersion:   ()               => ({ id: "tech_server_version_disclosure", module: "technology_detection", severity: "low", title: "Server header exposes software version" }),
};
const MODULES_OK = { dns: { resolves: true }, ssl: { https_available: true, https_probe_executed: true }, headers: { accessible: true, headers_assessed: true }, email_security: {} };
const MODULES_HEADERS_DEAD = { dns: { resolves: true }, ssl: { https_available: true, https_probe_executed: true }, headers: { accessible: false, incomplete: true, incomplete_reason: "probe_not_executed" }, email_security: {} };
const positiveAbsence = (domain = "acme.example.com") => ({
  tls_state: "positively_absent",
  https_available: false,
  https_probe_executed: true,
  certificate_evidence: { observed_at: "2026-08-09T12:00:05.000Z" },
  tls_positive_absence_evidence: {
    state: "positively_absent", execution: "completed",
    source_type: "approved_active_tls_collector",
    collector: "contract_fixture", collector_version: "1",
    endpoint: `https://${domain}`, assessed_domain: domain,
    observed_at: "2026-08-09T12:00:00.000Z",
    absence_outcome: "tls_service_absent", evidence_grade: "positive_absence",
  },
});
const QUALITY_OK = buildScanQuality(MODULES_OK);
const QUALITY_HEADERS_DEAD = buildScanQuality(MODULES_HEADERS_DEAD);

const run = (ws, findings, { modules = MODULES_OK, scanQuality = QUALITY_OK, scan = "scan_x", domainId = "d1", domain = "acme.example.com" } = {}) => {
  const effectiveModules = findings.some((finding) => finding?.id === "ssl_not_available")
    ? { ...modules, ssl: positiveAbsence(domain) }
    : modules;
  return evaluateWebsiteSecurityForScan(env, { workspace_id: ws, domain_id: domainId, domain, scan_id: scan, findings, modules: effectiveModules, scanQuality });
};

// ── 1. Registration — the silent-failure surface ────────────────────────────
{
  const src = LIFECYCLE_EVENT_SOURCES[WEBSITE_SECURITY_DOMAIN_KEY];
  ok("website_security is registered as an occurrence source", Boolean(src));
  eq("the source is the append-only events table",
     [src?.table, src?.fk, src?.type_column], ["website_security_events", "record_id", "event_type"]);
  // The interpolated allowlist must match the REAL schema, or the lookup raises, the
  // catch swallows it, and the domain is silently unalertable forever (the PR-B1 defect).
  const cols = db.prepare("PRAGMA table_info(website_security_events)").all().map((c) => c.name);
  for (const c of ["id", "record_id", "workspace_id", "event_type", "detail_json", "created_at"]) {
    ok(`website_security_events has the column the resolver reads: ${c}`, cols.includes(c));
  }
  const ccols = db.prepare("PRAGMA table_info(website_security_conditions)").all().map((c) => c.name);
  for (const c of ["workspace_id", "domain_id", "condition_key", "monitoring_status", "recurrence_type", "recurrence_band", "first_seen_at"]) {
    ok(`website_security_conditions has: ${c}`, ccols.includes(c));
  }

  // Every recurrence the evaluator can emit MUST be graded, or it fails closed.
  for (const key of ["ssl_not_available", "ssl_no_http_redirect", "header_missing_strict_transport_security", "header_malformed_content_security_policy"]) {
    const spec = websiteConditionSpec(key);
    ok(`${key}: maps to an actionable recurrence`, Boolean(spec?.recurrence));
    eq(`${key}: its recurrence is graded (never a default)`,
       severityForRecurrence(WEBSITE_SECURITY_DOMAIN_KEY, spec.recurrence), INHERIT_SEVERITY);
    // The condition_key IS the finding_type, so the registry must resolve it — else
    // the alert falls back to "review required" with no remediation.
    const r = resolveRemediation({ finding_type: key });
    ok(`${key}: resolves a canonical remediation`, r?.status === "resolved", `status=${r?.status}`);
    ok(`${key}: the remediation carries real customer copy, not a fallback`,
       Boolean(r?.customer_title) && Boolean(r?.recommended_action));
  }
  // Non-material Website Security findings must have NO actionable mapping at all.
  for (const key of ["header_weak_hsts", "canonical_url_uncertain", "security_headers_not_observed", "tech_server_version_disclosure"]) {
    eq(`${key}: is NOT an actionable condition (info/low evidence is not an event)`, websiteConditionSpec(key), null);
  }
  ok("recovery/baseline/unknown are not in the alertable vocabulary",
     WS_NON_ALERTABLE_EVENT_TYPES.every((t) => t !== MONITORING_CHANGED));
}

// ── 2. THE FLOOD GUARD — a 14-month backlog stays silent on day one ─────────
// The table is brand new, so alert_activation's baseline_count is 0 for every
// workspace, which trips emitManagedAlert's firstEverCondition hatch and makes the
// whole pre-existing backlog look "genuinely new by construction". Only the
// per-domain baseline marker stops it. This is the assertion that protects the
// first invited customers.
{
  const r = await run("ws1", [F.noHttps(), F.hstsMissing(), F.noRedirect(), F.malformedCsp()], { scan: "scan_1" });
  eq("the seeding pass examined the backlog", r.evaluated, 4);
  eq("THE FLOOD GUARD: a pre-existing backlog raises ZERO alerts", r.alerts, 0);
  eq("the seeding pass is marked as such", r.seeding, true);
  eq("no notification was written for the backlog", notifs("ws1").length, 0);
  eq("every backlog condition got a record", conds("ws1").length, 4);

  for (const key of ["ssl_not_available", "header_missing_strict_transport_security", "ssl_no_http_redirect", "header_malformed_content_security_policy"]) {
    const rec = condFor("ws1", key);
    eq(`${key}: marked baseline, not observed`, rec.monitoring_status, "baseline");
    const evs = allEvents(rec.id);
    eq(`${key}: got exactly one history event`, evs.length, 1);
    eq(`${key}: and it is a baseline, not an occurrence`, evs[0].event_type, WS_EVENT_BASELINE);
    eq(`${key}: has NO occurrence`, occurrences(rec.id).length, 0);
  }
  // The domain marker exists — including its detail — so a later pass knows.
  const marker = allEvents("d1").filter((e) => e.event_type === WS_EVENT_DOMAIN_BASELINE);
  eq("the domain baseline marker was written exactly once", marker.length, 1);

  // ...and it STAYS silent on every later pass, not merely the first. This is the
  // PR-B3 pass-two trap: a status that flips baseline→observed while the condition
  // is identical reads as a transition and releases the backlog one pass later.
  await run("ws1", [F.noHttps(), F.hstsMissing(), F.noRedirect(), F.malformedCsp()], { scan: "scan_2" });
  await run("ws1", [F.noHttps(), F.hstsMissing(), F.noRedirect(), F.malformedCsp()], { scan: "scan_3" });
  eq("the backlog stays silent across repeated passes", notifs("ws1").length, 0);
  eq("repeated passes append no occurrence", occurrences(condFor("ws1", "ssl_not_available").id).length, 0);

  // A current collector failure/bare false must be a true no-op for an existing
  // historical TLS condition. It must not manufacture an unknown transition,
  // mutate recurrence, verify/reopen a case, or emit an alert/email.
  const tlsBeforeUnavailable = condFor("ws1", "ssl_not_available");
  const tlsEventsBeforeUnavailable = allEvents(tlsBeforeUnavailable.id);
  const notificationsBeforeUnavailable = notifs("ws1");
  const casesBeforeUnavailable = db.prepare(
    "SELECT * FROM managed_cases WHERE workspace_id = ? ORDER BY id"
  ).all("ws1");
  const unavailableModules = {
    ...MODULES_OK,
    ssl: {
      tls_state: "unavailable",
      https_available: false,
      https_probe_executed: true,
      error: "collector failed",
    },
  };
  const unavailableResult = await evaluateWebsiteSecurityForScan(env, {
    workspace_id: "ws1",
    domain_id: "d1",
    domain: "acme.example.com",
    scan_id: "scan_tls_unavailable",
    findings: [F.noHttps(), F.hstsMissing(), F.noRedirect(), F.malformedCsp()],
    modules: unavailableModules,
    scanQuality: buildScanQuality(unavailableModules),
  });
  eq("unavailable TLS creates no lifecycle transition", unavailableResult.transitions, 0);
  eq("unavailable TLS creates no alert or email", unavailableResult.alerts, 0);
  eq("unavailable TLS creates no recovery", unavailableResult.resolved, 0);
  eq("unavailable TLS creates no unknown event", unavailableResult.unknown, 0);
  eq("unavailable TLS preserves the condition row byte-for-byte",
     condFor("ws1", "ssl_not_available"), tlsBeforeUnavailable);
  eq("unavailable TLS appends no lifecycle history",
     allEvents(tlsBeforeUnavailable.id), tlsEventsBeforeUnavailable);
  eq("unavailable TLS writes no notification",
     notifs("ws1"), notificationsBeforeUnavailable);
  eq("unavailable TLS creates or reopens no case",
     db.prepare("SELECT * FROM managed_cases WHERE workspace_id = ? ORDER BY id").all("ws1"),
     casesBeforeUnavailable);
  eq("a baselined record stays baseline while its condition is unchanged",
     condFor("ws1", "ssl_not_available").monitoring_status, "baseline");
  eq("the domain marker is not rewritten", allEvents("d1").filter((e) => e.event_type === WS_EVENT_DOMAIN_BASELINE).length, 1);
}

// ── 3. A genuinely NEW condition alerts exactly once ────────────────────────
{
  const before = notifs("ws1").length;
  const r = await run("ws1", [F.noHttps(), F.hstsMissing(), F.noRedirect(), F.malformedCsp(),
                              { id: "header_missing_content_security_policy", module: "headers", severity: "high", title: "Missing CSP Header" }],
                      { scan: "scan_4" });
  const rec = condFor("ws1", "header_missing_content_security_policy");
  ok("a post-baseline condition created a record", Boolean(rec));
  eq("...and it is observed, not baseline", rec.monitoring_status, "observed");
  eq("...and minted exactly ONE occurrence", occurrences(rec.id).length, 1);
  eq("...and alerted exactly once", notifs("ws1").length, before + 1);
  eq("...reported by the evaluator", r.alerts, 1);

  const n = notifs("ws1").at(-1);
  eq("the alert is attributed to the canonical domain", n.domain_key, WEBSITE_SECURITY_DOMAIN_KEY);
  eq("the alert kind is namespaced", n.type, "website_security.browser_protection_missing");
  eq("severity is INHERITED from the scan's own grade, not invented", n.severity, "high");
  ok("the alert carries the canonical remediation copy, not a fallback",
     !/review required/i.test(n.title), n.title);

  // THE PARITY ASSERTION: the resolver finds what the evaluator itself wrote.
  const occ = await findConditionOccurrence(env, {
    workspace_id: "ws1", domain_key: WEBSITE_SECURITY_DOMAIN_KEY,
    record_id: rec.id, recurrence_type: "browser_protection_missing",
  });
  ok("the resolver RESOLVES the evaluator's own transition", occ !== null);
  eq("occurrence id is the event id", occ?.occurrence_id, occurrences(rec.id)[0].id);
  eq("observed_at is the event's own created_at", occ?.observed_at, occurrences(rec.id)[0].created_at);

  // Unchanged rescan: silent.
  await run("ws1", [F.noHttps(), F.hstsMissing(), F.noRedirect(), F.malformedCsp(),
                    { id: "header_missing_content_security_policy", module: "headers", severity: "high", title: "Missing CSP Header" }],
            { scan: "scan_5" });
  eq("an unchanged rescan appends no new occurrence", occurrences(rec.id).length, 1);
  eq("an unchanged rescan sends nothing", notifs("ws1").length, before + 1);
}

// ── 4. Unavailable evidence is NEVER recovery ──────────────────────────────
// The headers probe times out. The condition vanishes from the findings — because
// scoring gates every header finding on `accessible`. Without the module-completion
// gate the evaluator would call that a fix.
{
  const rec = condFor("ws1", "header_missing_content_security_policy");
  const before = notifs("ws1").length;
  await run("ws1", [F.noHttps(), F.noRedirect()], { modules: MODULES_HEADERS_DEAD, scanQuality: QUALITY_HEADERS_DEAD, scan: "scan_6" });

  const after = condFor("ws1", "header_missing_content_security_policy");
  eq("an unreachable probe does NOT resolve the condition", after.monitoring_status, "unknown");
  ok("...and names why", ["module_not_assessed", "scan_partial"].includes(after.unknown_reason), after.unknown_reason);
  const evs = allEvents(rec.id);
  eq("...and records it as evidence_unknown, not condition_resolved", evs.at(-1).event_type, WS_EVENT_UNKNOWN);
  ok("...no condition_resolved event was ever written", !evs.some((e) => e.event_type === WS_EVENT_RESOLVED));
  eq("...and alerts nothing", notifs("ws1").length, before);

  // A later successful probe restores assessability. The condition is still there,
  // so this must NOT read as a reappearance — the customer changed nothing.
  await run("ws1", [F.noHttps(), F.hstsMissing(), F.noRedirect(), F.malformedCsp(),
                    { id: "header_missing_content_security_policy", module: "headers", severity: "high", title: "Missing CSP Header" }],
            { scan: "scan_7" });
  eq("a later successful probe restores observed", condFor("ws1", "header_missing_content_security_policy").monitoring_status, "observed");
  // unknown → observed IS a status transition, and the condition genuinely was
  // unverifiable in between, so one occurrence is honest. What must NOT happen is a
  // fabricated *recovery* in between — asserted above.
  ok("no condition_resolved was fabricated across the outage",
     !allEvents(rec.id).some((e) => e.event_type === WS_EVENT_RESOLVED));
}

// ── 5. Evidence downgrade is uncertainty, not a fix ────────────────────────
// A CDN challenge makes scoring emit the SAME condition at `info` instead of `high`.
// The condition did not go away; our evidence got weaker.
{
  const before = notifs("ws2").length;
  await run("ws2", [F.hstsMissing()], { scan: "s1", domainId: "d2", domain: "beta.example.com" });   // seed
  await run("ws2", [F.hstsMissing()], { scan: "s2", domainId: "d2", domain: "beta.example.com" });
  // Now a challenge: same finding id, downgraded to info.
  await run("ws2", [F.hstsUncertain()], { scan: "s3", domainId: "d2", domain: "beta.example.com" });
  const rec = condFor("ws2", "header_missing_strict_transport_security");
  eq("a downgrade to a non-material grade is UNKNOWN, not resolved", rec.monitoring_status, "unknown");
  eq("...and names the reason honestly", rec.unknown_reason, "evidence_uncertain");
  ok("...and writes no recovery event", !allEvents(rec.id).some((e) => e.event_type === WS_EVENT_RESOLVED));
  eq("...and tells the customer nothing", notifs("ws2").length, before);
}

// ── 6. Verified recovery, then reappearance ───────────────────────────────
{
  const rec = condFor("ws2", "header_missing_strict_transport_security");
  // The customer actually fixes it: condition absent AND the headers module ran.
  await run("ws2", [], { scan: "s4", domainId: "d2", domain: "beta.example.com" });
  const fixed = condFor("ws2", "header_missing_strict_transport_security");
  eq("absent + module assessed = a verified recovery", fixed.monitoring_status, "no_longer_observed");
  const evs = allEvents(rec.id);
  eq("the recovery is PERSISTED as history", evs.at(-1).event_type, WS_EVENT_RESOLVED);
  const beforeNotif = notifs("ws2").length;

  // It comes back. This IS news: it is new relative to an attributable prior state.
  await run("ws2", [F.hstsMissing()], { scan: "s5", domainId: "d2", domain: "beta.example.com" });
  const back = condFor("ws2", "header_missing_strict_transport_security");
  eq("a reappearance is observed again", back.monitoring_status, "observed");
  eq("...and mints a NEW occurrence", occurrences(rec.id).length, 1);
  eq("...and alerts", notifs("ws2").length, beforeNotif + 1);
  const detail = JSON.parse(occurrences(rec.id)[0].detail_json);
  eq("...labelled as a reappearance, from the persisted prior state", detail.reason, "condition_reappeared");
  eq("...from the recorded recovery", detail.from_monitoring_status, "no_longer_observed");
}

// ── 7. Worsening escalates exactly once (the PR-B2 band) ──────────────────
// A fresh workspace, because emitManagedAlert applies a per-(kind, entity) cooldown
// — critical 1h, high 4h. Firing a reappearance and a worsening milliseconds apart
// is suppressed by that cooldown, correctly: in production these are a scan apart.
// Testing the band on a clean entity is both realistic and what this asserts.
{
  db.prepare("INSERT INTO workspaces (id, owner_user_id, name) VALUES ('wsBand','u1','Band')").run();
  db.prepare("INSERT INTO workspace_members (id, workspace_id, user_id, role) VALUES ('mBand','wsBand','u1','owner')").run();
  // A workspace that has been watched for a month — the shape a band escalation
  // actually happens in.
  activate("wsBand", "2026-06-01T00:00:00Z");
  const D = { domainId: "dBand", domain: "band.example.com" };

  await run("wsBand", [], { scan: "b0", ...D });                       // seed the domain (clean)
  await run("wsBand", [F.hstsMissing("high")], { scan: "b1", ...D });  // genuine first condition
  const rec = condFor("wsBand", "header_missing_strict_transport_security");
  eq("a first condition after a CLEAN seeding pass alerts", notifs("wsBand").length, 1);
  eq("...at its own grade", notifs("wsBand").at(-1).severity, "high");
  eq("...with exactly one occurrence", occurrences(rec.id).length, 1);
  eq("...and the record carries the band", condFor("wsBand", "header_missing_strict_transport_security").recurrence_band, "high");

  // Same recurrence_type, worse grade. Without the band this is invisible and the
  // customer is never told it got worse. Clear the cooldown ledger to model the
  // hours-to-days gap between real scans.
  db.prepare("DELETE FROM alert_deliveries WHERE workspace_id='wsBand'").run();
  await run("wsBand", [F.hstsMissing("critical")], { scan: "b2", ...D });
  eq("a worsened grade mints exactly one more occurrence", occurrences(rec.id).length, 2);
  eq("...and alerts again", notifs("wsBand").length, 2);
  eq("...at the NEW grade, inherited from the scan", notifs("wsBand").at(-1).severity, "critical");
  eq("...and the record carries the new band", condFor("wsBand", "header_missing_strict_transport_security").recurrence_band, "critical");

  // Same grade again: silent. The band did not move, so nothing transitioned.
  db.prepare("DELETE FROM alert_deliveries WHERE workspace_id='wsBand'").run();
  await run("wsBand", [F.hstsMissing("critical")], { scan: "b3", ...D });
  eq("re-observing the worsened grade appends no occurrence", occurrences(rec.id).length, 2);
  eq("...and is silent", notifs("wsBand").length, 2);
}

// ── 8. Rule/version churn is not a customer event ─────────────────────────
// Non-material findings have no mapping at all, so shipping a new info/low detection
// rule cannot mint a record, an occurrence or an alert for anyone.
{
  const before = notifs("wsBand").length;
  const condsBefore = conds("wsBand").length;
  await run("wsBand", [F.hstsMissing("critical"), F.weakHsts(), F.techVersion(),
                    { id: "canonical_url_uncertain", module: "headers", severity: "info", title: "Canonical URL Could Not Be Confirmed" },
                    { id: "security_headers_not_observed", module: "headers", severity: "info", title: "Security Headers Not Fully Observed" }],
            { scan: "b4", domainId: "dBand", domain: "band.example.com" });
  eq("shipping new info/low rules creates no records", conds("wsBand").length, condsBefore);
  eq("...and alerts nobody", notifs("wsBand").length, before);
}

// ── 9. Tenant isolation + soft delete ─────────────────────────────────────
{
  ok("ws1's records are ws1's only", conds("ws1").every((r) => r.workspace_id === "ws1"));
  ok("ws2's records are ws2's only", conds("ws2").every((r) => r.workspace_id === "ws2"));
  ok("ws1's notifications never leaked to ws2", notifs("ws1").every((n) => n.workspace_id === "ws1"));

  // An identically-named condition in another tenant must never resolve here.
  const mine = condFor("ws1", "header_missing_strict_transport_security");
  const cross = await findConditionOccurrence(env, {
    workspace_id: "ws2", domain_key: WEBSITE_SECURITY_DOMAIN_KEY,
    record_id: mine.id, recurrence_type: "browser_protection_missing",
  });
  eq("an occurrence never resolves across tenants", cross, null);

  const dead = await run("wsDead", [F.noHttps()], { scan: "sd1", domainId: "dX", domain: "dead.example.com" });
  eq("a soft-deleted workspace is nonexistent to the lifecycle", dead.skipped, "workspace_inactive");
  eq("...and gets no records", conds("wsDead").length, 0);
  eq("...and no notifications", notifs("wsDead").length, 0);
}

// ── 10. The engine holds no sender and invents no identity ────────────────
{
  const src = fs.readFileSync(srcPath("engines", "website-security-lifecycle.js"), "utf8")
    .replace(/\/\*[\s\S]*?\*\//g, "").replace(/\/\/[^\n]*/g, "");
  ok("alerts only through the canonical consumer", src.includes("emitLifecycleAlert("));
  ok("no hand-rolled notification write", !/createNotificationEvent\(/.test(src));
  ok("no direct outbound channel send", !/deliverWorkspaceAlert\(/.test(src));
  ok("no direct emit that would bypass the watermark", !/emitManagedAlert\(/.test(src));
  ok("builds the canonical transition detail", src.includes("buildMonitoringTransitionDetail("));
  ok("guards the append with isMonitoringTransition", src.includes("isMonitoringTransition("));
  ok("the transition carries to_recurrence_type", /to_recurrence_type/.test(src));
  // Identity honesty: the evidence is domain-level, so the key must be too.
  ok("the identity is (workspace, domain, condition) — no invented hostname key",
     !/affected_hosts|final_url/.test(src));
  ok("recovery requires the detecting module to have run", src.includes("canVerify("));
}

// ── 11. MUTATION — would this suite catch the regressions it claims to? ───
{
  const original = fs.readFileSync(srcPath("engines", "website-security-lifecycle.js"), "utf8");

  // (a) Remove the flood guard: seeding always false => the backlog alerts.
  const noGuard = original.replace(
    "const seeding = !(await domainIsBaselined(env, workspace_id, domain_id));",
    "const seeding = false;",
  );
  ok("MUTATION (a) applied — the flood guard is where this suite thinks it is", noGuard !== original);

  // (b) Remove the completeness gate: absence always means recovery.
  const noGate = original.replace(
    "} else if (gate.canVerify(spec.module)) {",
    "} else if (true) {",
  );
  ok("MUTATION (b) applied — the recovery gate is where this suite thinks it is", noGate !== original);

  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "cm-ws-"));
  const runMutant = async (source, tag) => {
    const tmp = srcPath("engines", `.ws-lifecycle.mutant.${tag}.${path.basename(dir)}.js`);
    fs.writeFileSync(tmp, source);
    try { return await import(pathToFileURL(tmp).href); }
    finally { /* removed by caller */ }
  };

  try {
    // (a) the flood: a fresh workspace with a 4-condition backlog must now alert.
    const mA = await runMutant(noGuard, "a");
    db.prepare("INSERT INTO workspaces (id, owner_user_id, name) VALUES ('wsMutA','u1','MutA')").run();
    db.prepare("INSERT INTO workspace_members (id, workspace_id, user_id, role) VALUES ('mA','wsMutA','u1','owner')").run();
    const rA = await mA.evaluateWebsiteSecurityForScan(env, {
      workspace_id: "wsMutA", domain_id: "dA", domain: "mut-a.example.com", scan_id: "sA",
      findings: [F.noHttps(), F.hstsMissing(), F.noRedirect(), F.malformedCsp()],
      modules: { ...MODULES_OK, ssl: positiveAbsence("mut-a.example.com") }, scanQuality: QUALITY_OK,
    });
    ok("MUTANT (a): without the flood guard a pre-existing backlog ALERTS — the defect, reproduced",
       rA.alerts > 0 && notifs("wsMutA").length > 0, `alerts=${rA.alerts} notifs=${notifs("wsMutA").length}`);

    // (b) the false recovery: an unreachable probe now resolves the condition.
    const mB = await runMutant(noGate, "b");
    db.prepare("INSERT INTO workspaces (id, owner_user_id, name) VALUES ('wsMutB','u1','MutB')").run();
    db.prepare("INSERT INTO workspace_members (id, workspace_id, user_id, role) VALUES ('mB','wsMutB','u1','owner')").run();
    await mB.evaluateWebsiteSecurityForScan(env, {
      workspace_id: "wsMutB", domain_id: "dB", domain: "mut-b.example.com", scan_id: "sB1",
      findings: [F.hstsMissing()], modules: MODULES_OK, scanQuality: QUALITY_OK,
    });
    await mB.evaluateWebsiteSecurityForScan(env, {
      workspace_id: "wsMutB", domain_id: "dB", domain: "mut-b.example.com", scan_id: "sB2",
      findings: [], modules: MODULES_HEADERS_DEAD, scanQuality: QUALITY_HEADERS_DEAD,
    });
    const mutRec = db.prepare("SELECT * FROM website_security_conditions WHERE workspace_id='wsMutB' AND condition_key='header_missing_strict_transport_security'").get();
    eq("MUTANT (b): without the completeness gate a timed-out probe reads as a FIX — the defect, reproduced",
       mutRec.monitoring_status, "no_longer_observed");
    ok("MUTANT (b): and writes a fabricated recovery event",
       db.prepare("SELECT * FROM website_security_events WHERE record_id=? AND event_type=?").all(mutRec.id, WS_EVENT_RESOLVED).length > 0);
  } finally {
    for (const f of fs.readdirSync(srcPath("engines")).filter((f) => f.startsWith(".ws-lifecycle.mutant."))) {
      fs.rmSync(srcPath("engines", f), { force: true });
    }
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

globalThis.fetch = realFetch;
console.log(`\nwebsite-security-lifecycle: ${pass} passed, ${fail} failed`);
if (fail > 0) { console.error("website-security-lifecycle validation FAILED"); process.exit(1); }
console.log("website-security-lifecycle validation passed");
