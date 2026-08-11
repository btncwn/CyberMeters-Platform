#!/usr/bin/env node
//
// Evaluator → occurrence-resolver PARITY — DB-backed, CI-blocking.
//
// This exists because of a real defect that green tests missed.
//
// validate-alert-occurrence.js seeds monitoring_changed events with its OWN helper,
// which writes the shape the resolver expects. It therefore tested the resolver
// against a fixture the test author wrote — never against what the REAL evaluators
// emit. Certificates emitted the right shape; Identity and Shadow IT emitted
// monitoring_changed only for unrelated facts ("reappeared", "no_longer_observed",
// case-linkage), none carrying to_recurrence_type. So findConditionOccurrence always
// resolved null for those two domains, every condition looked pre-existing, and both
// consumers were silently incapable of ever alerting — while every suite stayed green.
//
// The lesson: a test that authors both sides of a contract proves only that the test
// agrees with itself. This drives the ACTUAL evaluator against real schema and asserts
// the resolver can find the occurrence the evaluator really wrote.
//
// Node 24+.
import fs from "node:fs";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const eng = (f) => pathToFileURL(path.join(root, "workers", "scan-api", "src", "engines", f)).href;
const { findConditionOccurrence, LIFECYCLE_EVENT_SOURCES } = await import(eng("alert-occurrence.js"));

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
// Occurrence-shaped events ONLY. `monitoring_changed` is still overloaded in these
// engines: it also records "reappeared" and "no_longer_observed" (shadow-it-inventory.js,
// identity-lifecycle.js). Only an event carrying to_recurrence_type is an OCCURRENCE, so
// counting the raw event_type conflates facts — which is why the resolver matches on the
// payload, not the type alone.
//
// The case-linkage row ({case_id, recurrence, updated_case}) used to be in that list too,
// under `monitoring_changed`, appended once per evaluation pass for as long as a condition
// persisted. It is now `case_recurrence_noted` in all three domains that wrote it. This
// filter is unchanged by that — the row never carried to_recurrence_type, so it was never
// counted here — but the reason it exists is now narrower than it was.
function occurrenceEvents(table, fk, id) {
  return db.prepare(`SELECT * FROM ${table} WHERE ${fk}=? AND event_type='monitoring_changed'`).all(id)
    .filter((e) => { try { return JSON.parse(e.detail_json || "{}").to_recurrence_type != null; } catch { return false; } });
}

const env = { cybermeters_db: makeD1(db), RESEND_API_KEY: "", ALERT_EMAIL_FROM: "alerts@cybermeters.com" };
const realFetch = globalThis.fetch;
globalThis.fetch = async () => new Response("{}", { status: 200 });

db.prepare("INSERT INTO users (id, email, name, plan, created_at) VALUES ('u1','o@example.com','o','free',datetime('now'))").run();
db.prepare("INSERT INTO workspaces (id, owner_user_id, name) VALUES ('ws1','u1','ws1')").run();
db.prepare("INSERT INTO domains (id, user_id, domain) VALUES ('dom1','u1','example.com')").run();
db.prepare("INSERT INTO workspace_domains (workspace_id, domain_id) VALUES ('ws1','dom1')").run();

// ── 1. Structural: EVERY wired domain must emit a matchable transition ───────
// The defect in one assertion: the resolver matches on detail.to_recurrence_type,
// so an evaluator that never writes that key can never be resolved. Parse each
// engine and require it builds the canonical detail via the shared helper.
{
  // Two shapes of evaluator, both of which must end up with a resolvable occurrence.
  //
  // LIFECYCLE engines own a record with a monitoring_status column and append their
  // own event, so they must use the shared helpers directly.
  const ENGINES = {
    certificates_trust: "certificate-lifecycle.js",
    identity_exposure: "identity-lifecycle.js",
    shadow_it_unmanaged_technology: "shadow-it-inventory.js",
    // PR-B3. Email Protection owns TWO record families in one engine, so this is
    // the lifecycle shape for the sender family (which has monitoring_status) and
    // the case shape for the hosted family (whose guard is the shipped
    // hosted_dns_entries state machine upstream). Both go through the same
    // helpers, so the assertions below hold for both.
    email_protection: "email-protection-lifecycle.js",
    website_security: "website-security-lifecycle.js",
    cyber_essentials_readiness: "ce-lifecycle.js",
  };
  // MANAGED-CASE engines (PR-B1) have no monitoring_status column — their transition
  // guard is the case state machine (canTransitionCase rejects a repeat), and they
  // delegate the append + emit to the shared bridge. Requiring them to call
  // buildMonitoringTransitionDetail directly would force back the per-domain
  // duplication this episode exists to remove.
  const CASE_ENGINES = {
    brand_protection: "brand-cases.js",
    attack_surface: "asm-cases.js",
  };
  eq("every wired domain has an event source",
     [...Object.keys(ENGINES), ...Object.keys(CASE_ENGINES)].sort(),
     Object.keys(LIFECYCLE_EVENT_SOURCES).sort());

  for (const [domain_key, file] of Object.entries(ENGINES)) {
    const src = fs.readFileSync(path.join(root, "workers", "scan-api", "src", "engines", file), "utf8")
      .split("\n").filter((l) => !l.trim().startsWith("//")).join("\n");
    ok(`${file}: builds the canonical transition detail`, src.includes("buildMonitoringTransitionDetail("),
       "an evaluator that hand-rolls the detail cannot be resolved");
    ok(`${file}: guards the append with isMonitoringTransition`, src.includes("isMonitoringTransition("),
       "unguarded appends mint a new occurrence every hour and re-alert forever");
    ok(`${file}: the transition carries to_recurrence_type`, /to_recurrence_type/.test(src),
       "the resolver matches on this key; without it the domain is silently unalertable");
  }

  // The bridge builds the canonical detail ONCE, on behalf of both case engines.
  const readEngine = (file) => fs.readFileSync(path.join(root, "workers", "scan-api", "src", "engines", file), "utf8")
    .split("\n").filter((l) => !l.trim().startsWith("//")).join("\n");
  const bridge = readEngine("alert-consumers.js");
  ok("the managed-case bridge builds the canonical transition detail",
     bridge.includes("buildMonitoringTransitionDetail("));
  ok("the managed-case bridge appends the monitoring_changed event itself",
     /INSERT INTO managed_case_events/.test(bridge) && /MONITORING_CHANGED/.test(bridge));

  for (const file of Object.values(CASE_ENGINES)) {
    const src = readEngine(file);
    ok(`${file}: alerts only through the shared case bridge`, src.includes("emitCaseLifecycleAlert("),
       "a case engine that sends directly bypasses occurrence, baseline, dedupe and the ledger");
    ok(`${file}: no hand-rolled notification write`, !/createNotificationEvent\(/.test(src),
       "writing notification_events directly is the defect PR-B1 removes");
    ok(`${file}: no direct outbound channel send`, !/deliverWorkspaceAlert\(/.test(src),
       "a domain engine must not hold a sender");
    ok(`${file}: does not call emitManagedAlert directly`, !/emitManagedAlert\(/.test(src),
       "a direct emit with no occurrence bypasses the watermark");
    ok(`${file}: does not hand-roll a monitoring_changed append`, !/monitoring_changed/.test(src),
       "the bridge owns the append so the detail shape cannot drift per domain");
    ok(`${file}: the legacy hand-rolled notifier is gone`,
       !/function notifyCase\(|function notifyBrandCase\(/.test(src));
  }
}

// ── 2. Behavioural: drive the REAL evaluator, resolve what IT wrote ──────────
// No hand-written events. The evaluator writes; the resolver reads.
{
  const { evaluateIdentityExposureMonitoring } = await import(eng("identity-lifecycle.js"));

  // A provider relationship change remains an alert-worthy recurrence without
  // manufacturing an endpoint-reachability claim.
  db.prepare(`INSERT INTO identity_exposure
      (id, workspace_id, domain_id, canonical_identity_key, provider_key, surface_type, primary_hostname,
       exposure_status, customer_classification, customer_action_status, monitoring_status, last_changed_at,
       first_seen_at, last_seen_at, confidence, created_at, updated_at)
    VALUES ('ie1','ws1','dom1','okta::login','okta','login_portal','sso.example.com',
       'observed','expected',NULL,'observed',datetime('now'),
       datetime('now','-40 days'), datetime('now'), 'high', datetime('now','-40 days'), datetime('now'))`).run();

  await evaluateIdentityExposureMonitoring(env, "ws1", { seenKeys: new Set(["dom1::okta::login"]) });

  const rec = db.prepare("SELECT * FROM identity_exposure WHERE id='ie1'").get();
  ok("identity: evaluator graded the provider-change recurrence", rec.recurrence_type === "provider_change",
     `recurrence_type=${rec.recurrence_type}`);

  const events = occurrenceEvents("identity_exposure_events", "record_id", "ie1");
  ok("identity: evaluator APPENDED an occurrence-shaped transition", events.length >= 1);
  eq("identity: exactly ONE occurrence for one condition", events.length, 1);

  // THE PARITY ASSERTION: the resolver finds the occurrence the evaluator wrote.
  const occ = await findConditionOccurrence(env, {
    workspace_id: "ws1", domain_key: "identity_exposure",
    record_id: "ie1", recurrence_type: rec.recurrence_type,
  });
  ok("identity: resolver RESOLVES the evaluator's own transition", occ !== null,
     "this is the assertion the previous suite lacked");
  if (occ) {
    ok("identity: occurrence id is the event id", events.some((e) => e.id === occ.occurrence_id));
    ok("identity: observed_at is the event's created_at", events.some((e) => e.created_at === occ.observed_at));
  }

  // Re-evaluating the SAME unchanged state must not mint a second occurrence.
  const before = events.length;
  await evaluateIdentityExposureMonitoring(env, "ws1", { seenKeys: new Set(["dom1::okta::login"]) });
  const after = occurrenceEvents("identity_exposure_events", "record_id", "ie1");
  eq("identity: unchanged re-evaluation appends NO new occurrence", after.length, before);
  eq("identity: the occurrence identity is unchanged across passes", after[0]?.id, events[0]?.id);
}

{
  const { evaluateShadowItMonitoring } = await import(eng("shadow-it-inventory.js"));

  // Real column names, taken from the migration — not invented. A seed that
  // guesses column names is how the previous suite drifted from reality.
  db.prepare(`INSERT INTO shadow_it_inventory
      (id, workspace_id, canonical_technology_key, display_name, provider, category, source_type,
       classification, monitoring_status, removal_status,
       first_seen_at, last_seen_at, created_at, updated_at)
    VALUES ('si1','ws1','dropbox','Dropbox','dropbox','saas','workspace_vendors',
       'rejected','observed','removed',
       datetime('now','-40 days'), datetime('now'), datetime('now','-40 days'), datetime('now'))`).run();

  await evaluateShadowItMonitoring(env, "ws1", { seenKeys: new Set(["dropbox"]) });

  const it = db.prepare("SELECT * FROM shadow_it_inventory WHERE id='si1'").get();
  ok("shadow-it: evaluator graded an alert-worthy recurrence", Boolean(it.recurrence_type),
     `recurrence_type=${it.recurrence_type}`);

  const events = occurrenceEvents("shadow_it_inventory_events", "item_id", "si1");
  ok("shadow-it: evaluator APPENDED an occurrence-shaped transition", events.length >= 1);
  eq("shadow-it: exactly ONE occurrence for one condition", events.length, 1);

  const occ = await findConditionOccurrence(env, {
    workspace_id: "ws1", domain_key: "shadow_it_unmanaged_technology",
    record_id: "si1", recurrence_type: it.recurrence_type,
  });
  ok("shadow-it: resolver RESOLVES the evaluator's own transition", occ !== null);
  if (occ) ok("shadow-it: occurrence id is the event id", events.some((e) => e.id === occ.occurrence_id));

  const before = events.length;
  await evaluateShadowItMonitoring(env, "ws1", { seenKeys: new Set(["dropbox"]) });
  const after = occurrenceEvents("shadow_it_inventory_events", "item_id", "si1");
  eq("shadow-it: unchanged re-evaluation appends NO new occurrence", after.length, before);
  eq("shadow-it: the occurrence identity is unchanged across passes", after[0]?.id, events[0]?.id);
}

// ── 3. The other monitoring_changed sites must not be mistaken for occurrences ─
// "reappeared" / "no_longer_observed" / case-linkage events are different facts.
// The resolver must ignore them, or an alert would borrow an unrelated timestamp.
{
  db.prepare(`INSERT INTO identity_exposure_events (id, record_id, workspace_id, actor_type, event_type, detail_json, created_at)
              VALUES ('iee_other','ie1','ws1','system','monitoring_changed', ?, datetime('now'))`)
    .run(JSON.stringify({ to: "no_longer_observed", note: "not_verified_removed" }));
  const occ = await findConditionOccurrence(env, {
    workspace_id: "ws1", domain_key: "identity_exposure", record_id: "ie1", recurrence_type: "some_other_recurrence",
  });
  eq("a non-recurrence monitoring_changed is never matched", occ, null);
}

globalThis.fetch = realFetch;
console.log(`\nalert-evaluator-parity: ${pass} passed, ${fail} failed`);
if (fail > 0) { console.error("alert-evaluator-parity validation FAILED"); process.exit(1); }
console.log("alert-evaluator-parity validation passed");
