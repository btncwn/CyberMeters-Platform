#!/usr/bin/env node
//
// PR-B4b — legacy alert cleanup. DB-backed, mutation-tested, CI-blocking.
//
// B4b finishes the legacy alert engine. Three things must hold, and each is
// asserted against real behaviour or the real source, never against a comment:
//
//   1. EXHAUSTIVE SUPPRESSION — every alert type the legacy processor can raise is
//      in OUTBOUND_SUPPRESSED_LEGACY_TYPES, so the legacy path cannot make an
//      outbound customer claim on ANY channel (email/Slack/Teams/webhook). The gate
//      is opt-in by construction, so an unlisted type would silently send: the set
//      being exhaustive is the whole safety property, and §2 extracts the types from
//      the source rather than trusting a hand-maintained list.
//
//   2. NO ADVISORY DEDUPE — isAlertDuplicate is gone, with zero callers. It was
//      read-then-write with no lock (two concurrent scans both send) and swallowed
//      errors into `false`, i.e. it failed OPEN into a duplicate send.
//
//   3. NO UNGATED TENANT SENDER — sendTakeoverAlert/sendSslExpiryAlert are deleted.
//      Both called the OPS-ONLY sendAlertEmail, which falls back to the OPERATOR's
//      inbox when given no recipient. They had no callers; that was the only reason
//      they were harmless.
//
// What B4b deliberately does NOT do is also pinned (§7), because a later reader
// will otherwise assume the silence means "not considered": the in-app
// notification_events row survives for every suppressed type, and the canonical
// pipeline is untouched.
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
const { OUTBOUND_SUPPRESSED_LEGACY_TYPES, processAlertsForWorkspace } = await import(eng("alerts.js"));

let pass = 0, fail = 0;
const ok = (n, c, d = "") => { c ? pass++ : fail++; if (!c) console.log(`FAIL ${n}${d ? " — " + d : ""}`); };
const eq = (n, g, w) => ok(n, JSON.stringify(g) === JSON.stringify(w), `got ${JSON.stringify(g)} want ${JSON.stringify(w)}`);

const alertsSrc = fs.readFileSync(srcPath("engines", "alerts.js"), "utf8");
const indexSrc = fs.readFileSync(srcPath("index.js"), "utf8");
// Comments describe intent; only code can send an email. Strip comments before
// asserting on behaviour, or a tombstone that merely NAMES a deleted function reads
// as the function still existing.
const stripComments = (s) => s.replace(/\/\*[\s\S]*?\*\//g, "").replace(/\/\/[^\n]*/g, "");
const alertsCode = stripComments(alertsSrc);
const indexCode = stripComments(indexSrc);

// ── 1. The advisory dedupe is gone ──────────────────────────────────────────
{
  ok("isAlertDuplicate is not defined", !/function\s+isAlertDuplicate/.test(alertsCode));
  eq("isAlertDuplicate has zero callers", (alertsCode.match(/isAlertDuplicate\s*\(/g) || []).length, 0);
  // The specific failure modes, so a reintroduction under a new name is still caught.
  ok("the legacy processor does not read-then-write notification_events to dedupe",
     !/SELECT[\s\S]{0,120}FROM notification_events[\s\S]{0,160}metadata_json/i.test(alertsCode));
  ok("no advisory dedupe helper survives anywhere in the engine",
     !/(isDuplicate|alreadyAlerted|wasRecentlyAlerted)\s*=\s*await/.test(alertsCode));
  // The canonical replacement is the DATABASE refusing the duplicate: an
  // INSERT OR IGNORE against the migration-087 partial UNIQUE index on
  // notification_events(domain_key, dedupe_key). No read, so no window to race.
  const managed = stripComments(fs.readFileSync(srcPath("engines", "managed-alerts.js"), "utf8"));
  ok("the canonical dedupe is an INSERT OR IGNORE, not a read-then-write",
     /INSERT OR IGNORE INTO notification_events[\s\S]{0,200}dedupe_key/i.test(managed));
  ok("the canonical dedupe decides from the DB's own rowcount, not a prior SELECT",
     /insert\.meta\?\.changes/.test(managed));
}

// ── 2. Suppression is EXHAUSTIVE over the legacy processor ──────────────────
// The set is opt-in, so a type absent from it SENDS. Extract every type the
// processor can actually raise from the source and require each one to be listed —
// this is what turns an opt-in gate into a closed set, and it is the assertion that
// would catch a future `triggerAlert({ type: "something_new" })`.
{
  const raised = [...alertsCode.matchAll(/triggerAlert\(\{\s*[\s\S]{0,80}?type:\s*"([a-z_]+)"/g)].map((m) => m[1]);
  ok("the legacy processor still raises types (the extractor is not silently empty)", raised.length > 0);
  eq("every raised type is accounted for", raised.sort(), ["new_finding", "new_vendor", "score_drop", "supply_chain_risk_increase"]);
  for (const t of raised) {
    ok(`${t}: raised by the legacy processor AND outbound-suppressed`, OUTBOUND_SUPPRESSED_LEGACY_TYPES.has(t));
  }
  eq("the suppressed set contains nothing that is not raised (no dead policy)",
     [...OUTBOUND_SUPPRESSED_LEGACY_TYPES].filter((t) => !raised.includes(t)), []);
}

// ── 3. Behaviour: no legacy condition reaches ANY outbound channel ───────────
// The assertions above read source. This one runs the real processor against a real
// SQLite schema with every sender instrumented, because a gate that reads correctly
// and sends anyway is exactly the failure being excluded.
{
  const db = new DatabaseSync(":memory:");
  const apply = (p) => { try { db.exec(fs.readFileSync(p, "utf8")); } catch { /* additive drift tolerated */ } };
  apply(path.join(root, "database", "schema.sql"));
  for (const f of fs.readdirSync(path.join(root, "database", "migrations")).filter((f) => f.endsWith(".sql")).sort()) {
    apply(path.join(root, "database", "migrations", f));
  }
  db.exec("PRAGMA foreign_keys = OFF");

  const makeD1 = (db) => {
    const wrap = (sql, args) => ({
      first: async (col) => { const r = db.prepare(sql).get(...args) ?? null; return col && r ? r[col] : r; },
      all: async () => ({ results: db.prepare(sql).all(...args), success: true, meta: {} }),
      run: async () => { const r = db.prepare(sql).run(...args); return { success: true, meta: { changes: r.changes } }; },
    });
    return { prepare(sql) { const b = wrap(sql, []); b.bind = (...a) => wrap(sql, a); return b; } };
  };

  db.prepare("INSERT INTO users (id, email, name, plan, created_at) VALUES ('u1','owner@example.com','o','professional',datetime('now'))").run();
  db.prepare("UPDATE users SET email_verified = 1 WHERE id = 'u1'").run();
  db.prepare(`INSERT INTO subscriptions (id, owner_user_id, plan, subscription_status, status, current_period_end, created_at, updated_at)
              VALUES ('s1','u1','professional','active','active',datetime('now','+30 days'),datetime('now'),datetime('now'))`).run();
  db.prepare("INSERT INTO workspaces (id, owner_user_id, name) VALUES ('ws1','u1','Acme')").run();
  db.prepare("INSERT INTO workspace_members (id, workspace_id, user_id, role) VALUES ('m1','ws1','u1','owner')").run();

  // Every outbound channel a workspace can configure — enabled, so that "nothing was
  // sent" is a real result and not an artefact of nothing being switched on.
  let chan = 0;
  for (const [type, target] of [["slack", "https://hooks.slack.com/services/T/B/x"],
                                ["teams", "https://acme.webhook.office.com/webhookb2/x"],
                                ["webhook", "https://alerts.example.com/hook"]]) {
    try {
      db.prepare(`INSERT INTO workspace_alert_channels (id, workspace_id, type, target_url, enabled, created_at)
                  VALUES (?, 'ws1', ?, ?, 1, datetime('now'))`).run(`ch${++chan}`, type, target);
    } catch { /* schema drift: channel table shape differs — §4 still covers the trunk */ }
  }

  // Instrument the real network boundary: any send at all is a failure.
  const sends = [];
  const realFetch = globalThis.fetch;
  globalThis.fetch = async (url, init) => {
    sends.push({ url: String(url), body: init?.body ? String(init.body).slice(0, 200) : null });
    return new Response(JSON.stringify({ id: "x" }), { status: 200, headers: { "content-type": "application/json" } });
  };

  const env = {
    cybermeters_db: makeD1(db),
    ALERT_EMAIL_FROM: "alerts@cybermeters.com",
    ALERT_EMAIL_TO: "operator@cybermeters.example",   // the operator inbox — must never receive
    RESEND_API_KEY: "re_test",
    FRONTEND_URL: "https://app.cybermeters.com",
  };

  // Drive every legacy condition at once: a 17-point score drop, two new
  // critical/high findings, a new vendor, and a supply-chain regression.
  db.prepare(`INSERT INTO workspace_vendors (id, workspace_id, vendor_name, category, status, first_seen, last_seen, created_at, updated_at)
              VALUES ('v1','ws1','Acme CDN','CDN','active',datetime('now'),datetime('now'),datetime('now'),datetime('now'))`).run();
  for (const [id, res, con, at] of [["h1", 90, "low", "-2 days"], ["h2", 60, "high", "-1 hours"]]) {
    db.prepare(`INSERT INTO workspace_supply_chain_history (id, workspace_id, resilience_score, concentration_level, calculated_at, created_at)
                VALUES (?, 'ws1', ?, ?, datetime('now', ?), datetime('now', ?))`).run(id, res, con, at, at);
  }

  const modules = {
    historical_changes: {
      has_previous: true, comparable: true, previous_score: 79, current_score: 62, score_change: -17,
      new_findings: [
        { id: "email_missing_dmarc", module: "email", severity: "critical", title: "No DMARC record" },
        { id: "ssl_not_available", module: "ssl", severity: "high", title: "No HTTPS" },
      ],
    },
    // new_vendor is gated on the vendor_risk module having detected vendors, so the
    // module must be present or that condition is never reached and its suppression
    // would go untested.
    vendor_risk: { detected: true, vendors: [{ vendor_name: "Acme CDN", category: "CDN" }] },
    ssl: {},
  };

  await processAlertsForWorkspace("ws1", "d1", "acme.example.com", "scan_1", 62, [], modules, "1970-01-01T00:00:00Z", env);

  const notifs = db.prepare("SELECT * FROM notification_events WHERE workspace_id='ws1'").all();
  const types = notifs.map((n) => n.type).sort();

  // The conditions were REACHED — otherwise "nothing sent" proves nothing at all.
  ok("the legacy processor ran and recorded its conditions in-app", notifs.length >= 3);
  ok("score_drop was reached", types.includes("score_drop"));
  ok("new_finding was reached", types.includes("new_finding"));
  ok("new_vendor was reached", types.includes("new_vendor"));

  // ...and NONE of them sent anything, on any transport.
  eq("no legacy condition sent on ANY channel (email/Slack/Teams/webhook)", sends, []);
  ok("the operator inbox received nothing", !sends.some((s) => JSON.stringify(s).includes("operator@cybermeters.example")));

  // Suppression is explicit and observable, with a precise reason — not silence.
  for (const n of notifs) {
    const meta = JSON.parse(n.metadata_json || "{}");
    eq(`${n.type}: recorded as skipped, not failed`, meta.email_delivery?.status, "skipped");
    eq(`${n.type}: names the actual reason`, meta.email_delivery?.reason, "evidence_not_attributable");
    ok(`${n.type}: sent_at is null (nothing was sent)`, n.sent_at === null);
  }
  // A deliberate policy is not a transient error: it must never be retried into a send.
  eq("no legacy delivery was queued for retry", db.prepare("SELECT COUNT(*) AS c FROM alert_deliveries WHERE workspace_id='ws1'").get().c, 0);
  // The legacy path must not have invented canonical identity to look canonical.
  ok("no canonical occurrence was minted by the legacy path",
     db.prepare("SELECT COUNT(*) AS c FROM alert_activation WHERE workspace_id='ws1'").get().c === 0);

  // Unchanged rescan: no delta => no condition => no repeat notification. This is the
  // property that replaced the 24h advisory window, so it is asserted rather than argued.
  //
  // The rescan must model what a real scan does to the tables the conditions read,
  // or this proves nothing: the scan pipeline APPENDS a supply-chain history row on
  // every pass, and the condition compares the two most recent rows. Without the
  // append, the same old (90 -> 60) pair would be re-compared forever and re-fire —
  // an artefact of the fixture, not of the engine. Appending an unchanged row is the
  // steady state actually being tested.
  db.prepare(`INSERT INTO workspace_supply_chain_history (id, workspace_id, resilience_score, concentration_level, calculated_at, created_at)
              VALUES ('h3','ws1',60,'high',datetime('now'),datetime('now'))`).run();
  const before = notifs.length;
  const steady = {
    historical_changes: { has_previous: true, comparable: true, previous_score: 62, current_score: 62, score_change: 0, new_findings: [] },
    vendor_risk: { detected: true, vendors: [{ vendor_name: "Acme CDN", category: "CDN" }] },
    ssl: {},
  };
  // startedAt in the future: the vendor's first_seen is older, so it is no longer new.
  await processAlertsForWorkspace("ws1", "d1", "acme.example.com", "scan_2", 62, [], steady, "2099-01-01T00:00:00Z", env);
  eq("an unchanged rescan raises no new legacy notification", db.prepare("SELECT COUNT(*) AS c FROM notification_events WHERE workspace_id='ws1'").get().c, before);
  eq("an unchanged rescan still sends nothing", sends, []);

  // Tenant isolation: one workspace's scan never writes another's history.
  ok("no notification leaked to another workspace",
     db.prepare("SELECT COUNT(*) AS c FROM notification_events WHERE workspace_id <> 'ws1'").get().c === 0);

  globalThis.fetch = realFetch;
}

// ── 4. Both outbound trunks stay gated, and there is no private sender ───────
{
  const guards = (alertsCode.match(/OUTBOUND_SUPPRESSED_LEGACY_TYPES\.has\(type\)/g) || []).length;
  eq("both outbound trunks (email + channels) are guarded", guards, 2);
  const proc = alertsCode.slice(alertsCode.indexOf("export async function processAlertsForWorkspace"));
  ok("the legacy processor has no private email sender",
     !/deliverEmail\(|sendCustomerEmail\(|sendAlertEmail\(/.test(proc));
  eq("the legacy processor reaches exactly one channel sender", (proc.match(/deliverWorkspaceAlert\(/g) || []).length, 1);
}

// ── 5. The two ungated tenant senders are gone ──────────────────────────────
{
  for (const fn of ["sendTakeoverAlert", "sendSslExpiryAlert"]) {
    ok(`${fn} is not defined`, !new RegExp(`function\\s+${fn}`).test(indexCode));
    ok(`${fn} has no callers`, !new RegExp(`${fn}\\s*\\(`).test(indexCode));
  }
  // sendAlertEmail itself is legitimate — it is the OPS sender. It must survive for
  // ops self-monitoring, and must not be reachable from a tenant alert path.
  const alertsFull = fs.readFileSync(srcPath("engines", "alerts.js"), "utf8");
  ok("the ops-only sendAlertEmail still exists (ops self-monitoring is not a tenant alert)",
     /export async function sendAlertEmail/.test(alertsFull));
  const opsCallers = (indexCode.match(/sendAlertEmail\(/g) || []).length;
  ok("sendAlertEmail retains only its ops caller(s)", opsCallers >= 1 && opsCallers <= 2);
}

// ── 6. MUTATION — would this suite catch the regressions it claims to? ───────
// Each assertion above is only worth what it fails on. Re-run the §3 behaviour
// against a processor whose suppression set has been emptied: it MUST send.
{
  const mutated = alertsSrc.replace(
    /export const OUTBOUND_SUPPRESSED_LEGACY_TYPES = Object\.freeze\(new Set\(\[[\s\S]*?\]\)\);/,
    "export const OUTBOUND_SUPPRESSED_LEGACY_TYPES = Object.freeze(new Set([]));",
  );
  ok("the mutation applied (the policy set is where this suite thinks it is)", mutated !== alertsSrc);

  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "cm-b4b-"));
  // alerts.js imports siblings by relative path, so the mutant must sit beside them.
  const tmp = srcPath("engines", `.alerts.mutant.${path.basename(dir)}.js`);
  fs.writeFileSync(tmp, mutated);
  try {
    const mutant = await import(pathToFileURL(tmp).href);
    eq("MUTANT: the suppression set is empty", mutant.OUTBOUND_SUPPRESSED_LEGACY_TYPES.size, 0);

    const db = new DatabaseSync(":memory:");
    const apply = (p) => { try { db.exec(fs.readFileSync(p, "utf8")); } catch { /* drift */ } };
    apply(path.join(root, "database", "schema.sql"));
    for (const f of fs.readdirSync(path.join(root, "database", "migrations")).filter((f) => f.endsWith(".sql")).sort()) {
      apply(path.join(root, "database", "migrations", f));
    }
    db.exec("PRAGMA foreign_keys = OFF");
    const makeD1 = (db) => {
      const wrap = (sql, args) => ({
        first: async (col) => { const r = db.prepare(sql).get(...args) ?? null; return col && r ? r[col] : r; },
        all: async () => ({ results: db.prepare(sql).all(...args), success: true, meta: {} }),
        run: async () => { const r = db.prepare(sql).run(...args); return { success: true, meta: { changes: r.changes } }; },
      });
      return { prepare(sql) { const b = wrap(sql, []); b.bind = (...a) => wrap(sql, a); return b; } };
    };
    db.prepare("INSERT INTO users (id, email, name, plan, created_at) VALUES ('u1','owner@example.com','o','professional',datetime('now'))").run();
    db.prepare("UPDATE users SET email_verified = 1 WHERE id = 'u1'").run();
    db.prepare(`INSERT INTO subscriptions (id, owner_user_id, plan, subscription_status, status, current_period_end, created_at, updated_at)
                VALUES ('s1','u1','professional','active','active',datetime('now','+30 days'),datetime('now'),datetime('now'))`).run();
    db.prepare("INSERT INTO workspaces (id, owner_user_id, name) VALUES ('ws1','u1','Acme')").run();
    db.prepare("INSERT INTO workspace_members (id, workspace_id, user_id, role) VALUES ('m1','ws1','u1','owner')").run();

    const sends = [];
    const realFetch = globalThis.fetch;
    globalThis.fetch = async (url, init) => {
      sends.push(String(url));
      return new Response(JSON.stringify({ id: "x" }), { status: 200, headers: { "content-type": "application/json" } });
    };
    const env = { cybermeters_db: makeD1(db), ALERT_EMAIL_FROM: "alerts@cybermeters.com", ALERT_EMAIL_TO: "operator@cybermeters.example", RESEND_API_KEY: "re_test", FRONTEND_URL: "https://app.cybermeters.com" };
    const modules = { historical_changes: { has_previous: true, comparable: true, previous_score: 79, current_score: 62, score_change: -17, new_findings: [{ id: "email_missing_dmarc", module: "email", severity: "critical", title: "No DMARC record" }] }, ssl: {} };
    await mutant.processAlertsForWorkspace("ws1", "d1", "acme.example.com", "scan_1", 62, [], modules, "1970-01-01T00:00:00Z", env);
    globalThis.fetch = realFetch;

    // With the policy emptied, the legacy path emails the customer again — the exact
    // behaviour B4b removes. If this does NOT happen, §3's "no sends" proves nothing.
    ok("MUTANT emails the customer once suppression is removed — §3's silence is real",
       sends.some((u) => u.includes("resend.com")));
  } finally {
    fs.rmSync(tmp, { force: true });
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

// ── 7. What B4b deliberately did NOT change ─────────────────────────────────
{
  // In-app history survives — suppression is about the CLAIM leaving the platform,
  // not about erasing the observation (historical integrity).
  ok("the notification INSERT is still reached for suppressed types",
     /INSERT INTO notification_events/.test(alertsCode));
  // The canonical pipeline is not touched by the legacy engine.
  ok("the legacy processor never calls emitManagedAlert",
     !/emitManagedAlert\(/.test(alertsCode.slice(alertsCode.indexOf("export async function processAlertsForWorkspace"))));
  ok("the legacy processor fabricates no domain_key",
     !/domain_key/.test(alertsCode.slice(alertsCode.indexOf("export async function processAlertsForWorkspace"))));
  ok("the legacy processor fabricates no dedupe_key",
     !/dedupe_key/.test(alertsCode.slice(alertsCode.indexOf("export async function processAlertsForWorkspace"))));
  // asset_change is a SEPARATE legacy path, deliberately retained: its evidence is
  // the append-only asset_events table and its dedupe is a DB unique constraint, not
  // an advisory read. B4b must not have silently disabled it.
  const assetSrc = stripComments(fs.readFileSync(srcPath("engines", "asset-alert-delivery.js"), "utf8"));
  ok("asset_change still delivers (retained: append-only evidence + DB-backed dedupe)",
     /deliverWorkspaceAlert\(|sendTenantAlertEmail\(/.test(assetSrc));
  ok("asset_change dedupe is a DB constraint, not an advisory read",
     /INSERT OR IGNORE INTO asset_alert_records/.test(assetSrc));
}

console.log(`\nalert-b4b-legacy-cleanup: ${pass} passed, ${fail} failed`);
if (fail > 0) { console.error("alert-b4b-legacy-cleanup validation FAILED"); process.exit(1); }
console.log("alert-b4b-legacy-cleanup validation passed");
