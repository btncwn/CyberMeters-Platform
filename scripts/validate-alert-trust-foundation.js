#!/usr/bin/env node
//
// Alert Trust Foundation (PR-A of Alerts Across All Eight Domains). CI-blocking.
//
// Two defects found while mapping the episode, both confirmed in code, neither
// reaching a real customer yet (the private beta is two founder-controlled
// domains) — latent, not active:
//
//   1. THE FREE-PLAN ENTITLEMENT BYPASS. emitManagedAlert checked entitlement.
//      NOTHING else did. processAlertsForWorkspace → triggerAlert sent real email
//      AND fanned out to Slack/Teams/webhook on every scan with no check at all,
//      while the `free` plan grants no "alerts" feature. Free workspaces received
//      paid alerts. The test fixtures encoded it: validate-alert-recipients seeded
//      plan 'free' and asserted successful delivery — and passed.
//
//   2. THE PREFERENCE CONTROL THAT DID NOTHING. Settings wrote per-USER rows under
//      {critical_finding, high_finding, daily_digest, email_alerts}; the pipeline
//      read WORKSPACE-wide rows under `event_type IN (<domain_key>.<recurrence>,
//      'all')`. Neither the user scope nor the vocabulary intersected, and nothing
//      ever wrote 'all' — so the lookup always missed and defaulted to ON,
//      silently overriding an explicit opt-out. A control that lies.
//
// The rule this file exists to enforce: NO outbound alert path may bypass the
// entitlement or the preference, and no unknown vocabulary may resolve to ON.
//
// Requires Node 24+ (node:sqlite).
import fs from "node:fs";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const eng = (f) => pathToFileURL(path.join(root, "workers", "scan-api", "src", "engines", f)).href;

const report = console.log.bind(console);
let pass = 0, fail = 0;
const ok = (n, c) => { c ? pass++ : fail++; if (!c) report("FAIL " + n); };
const eq = (n, g, w) => ok(`${n} (got ${JSON.stringify(g)}, want ${JSON.stringify(w)})`, g === w);

const {
  ALERT_EMAIL_FREQUENCIES, ALERT_PREF_EVENT, ALERT_PREF_CRITICAL_ONLY,
  alertEmailFrequencyForUser, channelEnabledForWorkspace, severityAllowedByFrequency,
  workspaceAlertsEntitled, resolveAlertEntitlement, GATED_CHANNELS,
} = await import(eng("alert-gate.js"));
const { sendTenantAlertEmail, deliverWorkspaceAlert } = await import(eng("alerts.js"));
const { TERMINAL_REASONS, RETRYABLE_REASONS } = await import(eng("managed-alerts.js"));
const { deliveryOutcome } = await import(eng("asset-alert-delivery.js"));

// ── Harness ─────────────────────────────────────────────────────────────────
AbortSignal.timeout = () => undefined;
let outboundEmails = [];
let outboundWebhooks = [];
const realFetch = globalThis.fetch;
globalThis.fetch = async (url, init) => {
  const u = String(url);
  if (u.includes("api.resend.com")) {
    outboundEmails.push(JSON.parse(init?.body || "{}"));
    return new Response(JSON.stringify({ id: "msg_test" }), { status: 200 });
  }
  outboundWebhooks.push(u);
  return new Response("ok", { status: 200 });
};

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
const env = { cybermeters_db: makeD1(db), RESEND_API_KEY: "re_test", ALERT_EMAIL_FROM: "alerts@cybermeters.com",
              ALERT_EMAIL_TO: "operator@cybermeters.com", FRONTEND_URL: "https://app.cybermeters.com" };

// ── Seed: a PAID workspace and a FREE workspace, each with two members ───────
const mkUser = (id, email) => {
  db.exec(`INSERT INTO users (id, email, name, plan, email_verified, created_at) VALUES ('${id}','${email}','${id}','free',1,datetime('now'))`);
};
const entitle = (userId, plan = "professional") => {
  db.exec(`INSERT INTO subscriptions (id, owner_user_id, plan, subscription_status, status, current_period_end, created_at, updated_at)
           VALUES ('sub_${userId}','${userId}','${plan}','active','active',datetime('now','+30 days'),datetime('now'),datetime('now'))`);
};
const mkWorkspace = (ws, owner) => db.exec(`INSERT INTO workspaces (id, owner_user_id, name) VALUES ('${ws}','${owner}','${ws}')`);
const member = (ws, uid, role) => db.exec(`INSERT INTO workspace_members (id, workspace_id, user_id, role) VALUES ('${ws}_${uid}','${ws}','${uid}','${role}')`);
const channel = (ws, id) => db.exec(`INSERT INTO workspace_alert_channels (id, workspace_id, channel_type, webhook_url, enabled, created_at)
                                     VALUES ('${id}','${ws}','webhook','https://hooks.example.com/${id}',1,datetime('now'))`);

mkUser("u_paid_owner", "owner@paid.example");  mkUser("u_paid_admin", "admin@paid.example");
mkUser("u_free_owner", "owner@free.example");  mkUser("u_free_admin", "admin@free.example");
entitle("u_paid_owner");                       // the FREE workspace's owner has no subscription row
mkWorkspace("ws_paid", "u_paid_owner"); member("ws_paid", "u_paid_owner", "owner"); member("ws_paid", "u_paid_admin", "admin");
mkWorkspace("ws_free", "u_free_owner"); member("ws_free", "u_free_owner", "owner"); member("ws_free", "u_free_admin", "admin");
channel("ws_paid", "ch_paid"); channel("ws_free", "ch_free");

const reset = () => { outboundEmails = []; outboundWebhooks = []; };
const setPref = (ws, uid, freq) => {
  db.exec(`DELETE FROM notification_preferences WHERE workspace_id='${ws}' AND ${uid === null ? "user_id IS NULL" : `user_id='${uid}'`}`);
  const master = freq !== "disabled" ? 1 : 0;
  const crit   = freq === "critical_only" ? 1 : 0;
  const u = uid === null ? "NULL" : `'${uid}'`;
  db.exec(`INSERT INTO notification_preferences (id, workspace_id, user_id, event_type, enabled, channel, created_at)
           VALUES ('np_${ws}_${uid || "ws"}_m','${ws}',${u},'${ALERT_PREF_EVENT}',${master},'email',datetime('now'))`);
  db.exec(`INSERT INTO notification_preferences (id, workspace_id, user_id, event_type, enabled, channel, created_at)
           VALUES ('np_${ws}_${uid || "ws"}_c','${ws}',${u},'${ALERT_PREF_CRITICAL_ONLY}',${crit},'email',datetime('now'))`);
};
const clearPrefs = () => db.exec("DELETE FROM notification_preferences");
const send = (ws, severity = "high") => sendTenantAlertEmail(env, ws, { subject: "s", text: "t", html: "<p>t</p>", severity });

// ── 1. A free workspace receives NOTHING outbound, on any path ───────────────
{
  reset(); clearPrefs();
  eq("free workspace is not entitled", await workspaceAlertsEntitled(env, "ws_free"), false);

  const r = await send("ws_free", "critical");   // even at CRITICAL
  eq("free: email refused", r.sent, false);
  eq("free: honest terminal reason", r.reason, "feature_not_entitled");
  eq("free: ZERO outbound emails", outboundEmails.length, 0);

  const d = await deliverWorkspaceAlert(env, "ws_free", { kind: "k", severity: "critical", title: "t", summary: "s" });
  eq("free: ZERO webhook deliveries", outboundWebhooks.length, 0);
  eq("free: channel fan-out reports the reason", d.suppressed_reason, "feature_not_entitled");
  eq("free: channel fan-out attempted nothing", d.attempted, 0);

  // The channel TEST endpoint is a delivery too — it must not be a side door.
  reset();
  const t = await deliverWorkspaceAlert(env, "ws_free", { kind: "test", severity: "info", title: "t", summary: "s" }, { channelId: "ch_free" });
  eq("free: channel TEST send is also refused", t.suppressed_reason, "feature_not_entitled");
  eq("free: channel TEST produced no outbound request", outboundWebhooks.length, 0);
}

// ── 2. A paid, entitled workspace may proceed ───────────────────────────────
{
  reset(); clearPrefs();
  eq("paid workspace is entitled", await workspaceAlertsEntitled(env, "ws_paid"), true);
  const r = await send("ws_paid", "high");
  eq("paid: email sent", r.sent, true);
  eq("paid: exactly one outbound email", outboundEmails.length, 1);
  eq("paid: default is ON when no preference is stored", (r.recipients || []).length, 2);

  reset();
  const d = await deliverWorkspaceAlert(env, "ws_paid", { kind: "k", severity: "high", title: "t", summary: "s" });
  ok("paid: channel fan-out proceeds", d.attempted >= 1);
  ok("paid: no suppression reason", !d.suppressed_reason);
}

// ── 3. A user's own email preference suppresses only their address ───────────
{
  reset(); clearPrefs();
  setPref("ws_paid", "u_paid_admin", "disabled");
  const r = await send("ws_paid", "high");
  eq("one member opted out → still sent to the other", r.sent, true);
  eq("opted-out member is not mailed", (r.recipients || []).includes("admin@paid.example"), false);
  eq("the other member IS mailed", (r.recipients || []).includes("owner@paid.example"), true);
  eq("exactly one outbound email", outboundEmails.length, 1);

  // ...and the reverse: another user's preference cannot suppress THIS user.
  const pref = await alertEmailFrequencyForUser(env, "ws_paid", "u_paid_owner");
  eq("another user's opt-out does not change this user's preference", pref.frequency, "all_alerts");
}

// ── 4. Everyone opted out → nothing sent, honestly ──────────────────────────
{
  reset(); clearPrefs();
  setPref("ws_paid", "u_paid_owner", "disabled");
  setPref("ws_paid", "u_paid_admin", "disabled");
  const r = await send("ws_paid", "critical");
  eq("all opted out: nothing sent even at critical", r.sent, false);
  eq("all opted out: reason", r.reason, "channel_disabled");
  eq("all opted out: ZERO outbound emails", outboundEmails.length, 0);
  ok("all opted out: reason is terminal (never retried)", TERMINAL_REASONS.has(r.reason));
}

// ── 5. critical_only means EXACTLY critical ────────────────────────────────
{
  for (const sev of ["high", "medium", "low", "info"]) {
    reset(); clearPrefs();
    setPref("ws_paid", "u_paid_owner", "critical_only");
    setPref("ws_paid", "u_paid_admin", "critical_only");
    const r = await send("ws_paid", sev);
    eq(`critical_only: '${sev}' is suppressed`, r.sent, false);
    eq(`critical_only: '${sev}' reason is preference_filtered`, r.reason, "preference_filtered");
    eq(`critical_only: '${sev}' produced ZERO emails`, outboundEmails.length, 0);
  }
  reset(); clearPrefs();
  setPref("ws_paid", "u_paid_owner", "critical_only");
  setPref("ws_paid", "u_paid_admin", "critical_only");
  const r = await send("ws_paid", "critical");
  eq("critical_only: 'critical' IS delivered", r.sent, true);
  eq("critical_only: exactly one outbound email", outboundEmails.length, 1);

  // The rule itself, stated directly: critical_only is not "high or above".
  ok("critical_only never widens to high", severityAllowedByFrequency("critical_only", "high") === false);
  ok("critical_only allows critical", severityAllowedByFrequency("critical_only", "critical") === true);
  ok("all_alerts allows every severity", ["critical", "high", "medium", "low", "info"].every((s) => severityAllowedByFrequency("all_alerts", s)));
  ok("disabled allows nothing", ["critical", "high"].every((s) => severityAllowedByFrequency("disabled", s) === false));
}

// ── 6. An unlabelled alert cannot satisfy critical_only ─────────────────────
{
  reset(); clearPrefs();
  setPref("ws_paid", "u_paid_owner", "critical_only");
  setPref("ws_paid", "u_paid_admin", "critical_only");
  const r = await sendTenantAlertEmail(env, "ws_paid", { subject: "s", text: "t", html: "<p>t</p>" }); // no severity
  eq("missing severity does not slip past critical_only", r.sent, false);
  eq("missing severity: ZERO emails", outboundEmails.length, 0);
  ok("severity null is not critical", severityAllowedByFrequency("critical_only", null) === false);
  ok("severity undefined is not critical", severityAllowedByFrequency("critical_only", undefined) === false);
}

// ── 7. UNKNOWN vocabulary can never default to outbound ON ──────────────────
// This is the exact live bug: the pipeline read a vocabulary nothing wrote, missed,
// and defaulted ON — overriding an explicit opt-out stored under another name.
{
  ok("an unknown frequency is not allowed", severityAllowedByFrequency("weekly_roundup", "critical") === false);
  ok("an empty frequency is not allowed", severityAllowedByFrequency("", "critical") === false);
  ok("a null frequency is not allowed", severityAllowedByFrequency(null, "critical") === false);
  ok("the removed daily_digest is not allowed", severityAllowedByFrequency("daily_digest", "critical") === false);

  // A row in the OLD vocabulary must not be read as an enable.
  reset(); clearPrefs();
  db.exec(`INSERT INTO notification_preferences (id, workspace_id, user_id, event_type, enabled, channel, created_at)
           VALUES ('np_legacy','ws_paid','u_paid_owner','email_alerts',1,'email',datetime('now'))`);
  const pref = await alertEmailFrequencyForUser(env, "ws_paid", "u_paid_owner");
  eq("a legacy-vocabulary row is ignored, not misread", pref.frequency, "all_alerts");
  ok("legacy vocabulary lookup still succeeds (not an error)", pref.ok === true);
}

// ── 8. daily_digest is gone and cannot silently become something else ───────
{
  eq("supported frequencies are exactly three", ALERT_EMAIL_FREQUENCIES.length, 3);
  ok("all_alerts supported", ALERT_EMAIL_FREQUENCIES.includes("all_alerts"));
  ok("critical_only supported", ALERT_EMAIL_FREQUENCIES.includes("critical_only"));
  ok("disabled supported", ALERT_EMAIL_FREQUENCIES.includes("disabled"));
  ok("daily_digest is NOT supported", !ALERT_EMAIL_FREQUENCIES.includes("daily_digest"));
  ok("the frequency list is frozen", Object.isFrozen(ALERT_EMAIL_FREQUENCIES));

  // It must not be aliased to a neighbouring behaviour.
  ok("daily_digest does not behave as all_alerts", severityAllowedByFrequency("daily_digest", "high") === false);
  ok("daily_digest does not behave as critical_only", severityAllowedByFrequency("daily_digest", "critical") === false);

  // No daily digest sender exists anywhere — the reason it was removed. Comments
  // are stripped first: the comments that EXPLAIN the removal necessarily name it,
  // and a rule that forbids explaining a decision would delete its own rationale.
  const stripComments = (s) => s.replace(/\/\*[\s\S]*?\*\//g, "").replace(/\/\/[^\n]*/g, "");
  const workerSrc = path.join(root, "workers", "scan-api", "src");
  const files = [];
  (function walk(d) { for (const f of fs.readdirSync(d, { withFileTypes: true })) {
    if (f.isDirectory()) walk(path.join(d, f.name)); else if (f.name.endsWith(".js")) files.push(path.join(d, f.name));
  } })(workerSrc);
  const digestRefs = files.filter((f) => /daily_digest/.test(stripComments(fs.readFileSync(f, "utf8"))));
  eq(`no backend CODE references daily_digest any more (${digestRefs.map((f) => path.basename(f)).join(", ") || "none"})`, digestRefs.length, 0);

  const settings = stripComments(fs.readFileSync(path.join(root, "frontend", "src", "pages", "SettingsPage.jsx"), "utf8"));
  ok("Settings no longer offers a Daily digest option", !/daily_digest/.test(settings));
  ok("Settings no longer promises a daily summary email",
     !/summary email per day/i.test(settings) && !/Daily digest/i.test(settings));
}

// ── 9. Preferences cannot leak across workspaces ───────────────────────────
{
  reset(); clearPrefs();
  // The SAME user id opts out in ws_free; ws_paid must be unaffected.
  db.exec(`INSERT INTO notification_preferences (id, workspace_id, user_id, event_type, enabled, channel, created_at)
           VALUES ('np_x','ws_free','u_paid_owner','${ALERT_PREF_EVENT}',0,'email',datetime('now'))`);
  const inPaid = await alertEmailFrequencyForUser(env, "ws_paid", "u_paid_owner");
  eq("another workspace's opt-out does not leak in", inPaid.frequency, "all_alerts");
  const inFree = await alertEmailFrequencyForUser(env, "ws_free", "u_paid_owner");
  eq("the opt-out applies in its own workspace", inFree.frequency, "disabled");

  // Channel preference is likewise workspace-scoped.
  db.exec(`INSERT INTO notification_preferences (id, workspace_id, user_id, event_type, enabled, channel, created_at)
           VALUES ('np_ch','ws_free',NULL,'${ALERT_PREF_EVENT}',0,'webhook',datetime('now'))`);
  eq("ws_free webhook disabled", await channelEnabledForWorkspace(env, "ws_free", { channel: "webhook" }), false);
  eq("ws_paid webhook unaffected", await channelEnabledForWorkspace(env, "ws_paid", { channel: "webhook" }), true);
}

// ── 10. Fail closed on ambiguity ───────────────────────────────────────────
{
  const brokenEnv = { ...env, cybermeters_db: { prepare() { throw new Error("D1 down"); } } };
  eq("entitlement lookup failure → not entitled (fail closed)", await workspaceAlertsEntitled(brokenEnv, "ws_paid"), false);
  const ent = await resolveAlertEntitlement(brokenEnv, "ws_paid");
  eq("...but it is reported as UNDETERMINED, not as 'not entitled'", ent.ok, false);
  eq("channel preference lookup failure → disabled (fail closed)",
     await channelEnabledForWorkspace(brokenEnv, "ws_paid", { channel: "webhook" }), false);
  const pref = await alertEmailFrequencyForUser(brokenEnv, "ws_paid", "u_paid_owner");
  eq("email preference lookup failure → ok:false (caller must fail closed)", pref.ok, false);

  reset();
  const r = await sendTenantAlertEmail(brokenEnv, "ws_paid", { subject: "s", text: "t", html: "<p>t</p>", severity: "critical" });
  eq("broken D1: nothing sent", r.sent, false);
  eq("broken D1: ZERO outbound emails", outboundEmails.length, 0);
  ok("broken D1: reason is RETRYABLE, not a permanent fact about the customer",
     RETRYABLE_REASONS.has(r.reason) && r.reason !== "feature_not_entitled");
}

// ── 11. Suppressions are terminal; they must never be retried forever ──────
{
  for (const reason of ["feature_not_entitled", "channel_disabled", "preference_filtered", "no_verified_recipient"]) {
    ok(`'${reason}' is terminal`, TERMINAL_REASONS.has(reason));
    ok(`'${reason}' is NOT retryable`, !RETRYABLE_REASONS.has(reason));
    eq(`asset-alert sweep records '${reason}' as skipped, not failed`,
       deliveryOutcome({ sent: false, reason }).status, "skipped");
  }
  ok("entitlement_lookup_failed IS retryable", RETRYABLE_REASONS.has("entitlement_lookup_failed"));
  ok("entitlement_lookup_failed is not terminal", !TERMINAL_REASONS.has("entitlement_lookup_failed"));
  eq("a real send failure is still retried", deliveryOutcome({ sent: false, reason: "send_failed" }).status, "failed");
}

// ── 12. Structural: no outbound path may bypass the gate ──────────────────
{
  const alertsSrc = fs.readFileSync(path.join(root, "workers", "scan-api", "src", "engines", "alerts.js"), "utf8");

  ok("the email chokepoint checks entitlement", /resolveAlertEntitlement\(env, workspaceId\)/.test(alertsSrc));
  ok("the email chokepoint checks the per-user preference", /alertEmailFrequencyForUser\(env, workspaceId, r\.user_id\)/.test(alertsSrc));
  ok("the email chokepoint checks severity", /severityAllowedByFrequency\(pref\.frequency, severity\)/.test(alertsSrc));
  ok("the channel chokepoint checks entitlement", /deliverWorkspaceAlert[\s\S]{0,900}?workspaceAlertsEntitled/.test(alertsSrc));

  // The legacy scan-alert path must no longer hold recipients or send directly.
  ok("legacy triggerAlert no longer calls sendCustomerEmail",
     !/sendCustomerEmail\(/.test(alertsSrc.replace(/\/\/[^\n]*/g, "")));
  ok("sendCustomerEmail is no longer even imported", !/import[^\n]*sendCustomerEmail/.test(alertsSrc));
  ok("legacy triggerAlert routes email through the chokepoint",
     /processAlertsForWorkspace[\s\S]*?sendTenantAlertEmail\(env, workspaceId/.test(alertsSrc));
  ok("the recipient resolver carries user_id (per-user preferences need it)",
     /SELECT DISTINCT u\.id AS user_id, u\.email/.test(alertsSrc));

  // Dead code stayed dead.
  ok("shouldSendAlert is gone", !/function shouldSendAlert/.test(alertsSrc));
  ok("buildAlertEmail is gone", !/function buildAlertEmail/.test(alertsSrc));

  // No engine may reach a customer with an ALERT except through the chokepoint.
  //
  // The boundary is sendAlertEmail — the OPS-ONLY sender that falls back to the
  // operator inbox (the PR #86 defect). sendCustomerEmail is deliberately NOT
  // forbidden: it is the general customer-email helper and stripe.js correctly uses
  // it for billing lifecycle mail ("your subscription has been cancelled"), which is
  // not an alert and has no entitlement or alert-preference to honour. Forbidding it
  // outright would be a rule that sounds strict and means the wrong thing.
  const engines = fs.readdirSync(path.join(root, "workers", "scan-api", "src", "engines")).filter((f) => f.endsWith(".js"));
  const offenders = engines.filter((f) => {
    if (f === "alerts.js" || f === "alert-gate.js") return false;
    const src = fs.readFileSync(path.join(root, "workers", "scan-api", "src", "engines", f), "utf8").replace(/\/\/[^\n]*/g, "");
    return /\bsendAlertEmail\(/.test(src);
  });
  eq(`no engine uses the operator-fallback sender (offenders: ${offenders.join(", ") || "none"})`, offenders.length, 0);

  // And the alert engines specifically must not hand-roll a send.
  const alertEngines = ["managed-alerts.js", "asset-alert-delivery.js", "dmarc-alerts.js", "asm-cases.js", "brand-cases.js"];
  const handRolled = alertEngines.filter((f) => {
    const p = path.join(root, "workers", "scan-api", "src", "engines", f);
    if (!fs.existsSync(p)) return false;
    const src = fs.readFileSync(p, "utf8").replace(/\/\/[^\n]*/g, "");
    return /\bdeliverEmail\(|\bsendCustomerEmail\(/.test(src);
  });
  eq(`alert engines send only via the chokepoint (offenders: ${handRolled.join(", ") || "none"})`, handRolled.length, 0);

  // The gate is defined once.
  const gateSrc = fs.readFileSync(path.join(root, "workers", "scan-api", "src", "engines", "alert-gate.js"), "utf8");
  ok("entitlement is defined in exactly one module",
     /export async function resolveAlertEntitlement/.test(gateSrc)
     && !/export async function resolveAlertEntitlement/.test(fs.readFileSync(path.join(root, "workers", "scan-api", "src", "engines", "managed-alerts.js"), "utf8")));

  // Settings must write the vocabulary the pipeline reads — the whole defect.
  const routeSrc = fs.readFileSync(path.join(root, "workers", "scan-api", "src", "routes", "workspace-activity.js"), "utf8");
  ok("Settings PUT writes the canonical vocabulary", new RegExp(`\\[ALERT_PREF_EVENT\\]`).test(routeSrc));
  ok("Settings PUT validates against the canonical list", /ALERT_EMAIL_FREQUENCIES\.includes\(email_frequency\)/.test(routeSrc));
  ok("Settings GET reads through the pipeline's own resolver", /alertEmailFrequencyForUser\(env, workspaceId, prefUser\.id\)/.test(routeSrc));
  ok("Settings no longer writes the private legacy vocabulary",
     !/critical_finding:\s|high_finding:\s|daily_digest:\s/.test(routeSrc));
}

// ── 13. in_app is never gated — the evidence record always survives ────────
{
  ok("in_app is not a gated channel", !GATED_CHANNELS.includes("in_app"));
  ok("gated channels are exactly the outbound four",
     ["email", "webhook", "slack", "teams"].every((c) => GATED_CHANNELS.includes(c)) && GATED_CHANNELS.length === 4);
}

globalThis.fetch = realFetch;
report(`\nAlert trust foundation: ${pass}/${pass + fail} passed`);
if (fail > 0) process.exit(1);
