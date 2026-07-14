#!/usr/bin/env node
//
// Canonical managed-alert pipeline — DB-backed, CI-blocking.
//
// Proves the founder-ruled contract for Alerts Across All Eight Domains:
//   • proactive DELIVERY is the paid feature; the canonical in-app event is not
//   • entitlement resolves through the canonical helper — no plan names inlined
//   • a customer-disabled channel is NOT overridden by critical severity
//   • soft-deleted workspaces receive nothing
//   • dedupe is a DB guarantee, not a read-then-write race
//   • terminal suppressions never retry; provider/lookup failures may
//   • every outcome is recorded in the append-only ledger with an explicit reason
//
// Node 24+.
import fs from "node:fs";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const eng = (f) => pathToFileURL(path.join(root, "workers", "scan-api", "src", "engines", f)).href;
const {
  emitManagedAlert, buildAlertDedupeKey, isTerminalReason, reasonIsRetryable,
  TERMINAL_REASONS, RETRYABLE_REASONS, MONITORING_CHANNELS, ALERTS_FEATURE_KEY,
} = await import(eng("managed-alerts.js"));
const { PLAN_FEATURES } = await import(eng("entitlements.js"));

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
function user(id, email, plan) {
  db.prepare("INSERT INTO users (id, email, name, plan, created_at) VALUES (?, ?, ?, ?, datetime('now'))").run(id, email, id, plan);
  db.prepare("UPDATE users SET email_verified = 1 WHERE id = ?").run(id);
}
function workspace(ws, owner, { deleted = false } = {}) {
  db.prepare("INSERT INTO workspaces (id, owner_user_id, name) VALUES (?, ?, ?)").run(ws, owner, ws);
  db.prepare("INSERT INTO workspace_members (id, workspace_id, user_id, role) VALUES (?, ?, ?, 'owner')").run(`${ws}_m`, ws, owner);
  if (deleted) db.prepare("UPDATE workspaces SET deleted_at = datetime('now') WHERE id = ?").run(ws);
}
// Mirrors what the Stripe webhook writes: getUserPlan reads subscriptions by
// owner_user_id and requires an active status and an unexpired period.
function subscribe(userId, plan) {
  db.prepare(`INSERT INTO subscriptions
      (id, owner_user_id, plan, subscription_status, status, current_period_end, created_at, updated_at)
    VALUES (?, ?, ?, 'active', 'active', datetime('now', '+30 days'), datetime('now'), datetime('now'))`)
    .run(`sub_${userId}`, userId, plan);
}

user("u_paid", "paid@example.com", "professional");   subscribe("u_paid", "professional");
user("u_free", "free@example.com", "free");
user("u_dead", "dead@example.com", "professional");   subscribe("u_dead", "professional");

workspace("ws_paid", "u_paid");
workspace("ws_free", "u_free");
workspace("ws_dead", "u_dead", { deleted: true });

const env = {
  cybermeters_db: makeD1(db),
  ALERT_EMAIL_FROM: "alerts@cybermeters.com",
  ALERT_EMAIL_TO: "operator@cybermeters.example",
  RESEND_API_KEY: "re_test",
};

const ledger = (ws) => db.prepare("SELECT * FROM alert_deliveries WHERE workspace_id = ? ORDER BY created_at, channel").all(ws);
const notifs = (ws) => db.prepare("SELECT * FROM notification_events WHERE workspace_id = ?").all(ws);
const alert = (over = {}) => ({
  workspace_id: "ws_paid", domain_key: "certificates_trust", kind: "cert_expiring",
  severity: "high", title: "Certificate expiring", message: "Renew it.",
  dedupe_key: buildAlertDedupeKey({ domain_key: "certificates_trust", kind: "cert_expiring", subject: "www.example.com" }),
  ...over,
});

// ── 1. Deterministic identity ────────────────────────────────────────────────
{
  const a = buildAlertDedupeKey({ domain_key: "certificates_trust", kind: "cert_expiring", subject: "WWW.Example.com" });
  const b = buildAlertDedupeKey({ domain_key: "certificates_trust", kind: "cert_expiring", subject: "www.example.com" });
  eq("dedupe key is case-stable", a, b);
  ok("dedupe key separates domains",
     buildAlertDedupeKey({ domain_key: "identity_exposure", kind: "cert_expiring", subject: "x" }) !==
     buildAlertDedupeKey({ domain_key: "certificates_trust", kind: "cert_expiring", subject: "x" }));
  ok("dedupe key separates periods",
     buildAlertDedupeKey({ domain_key: "d", kind: "k", subject: "s", period: "2026-07" }) !==
     buildAlertDedupeKey({ domain_key: "d", kind: "k", subject: "s", period: "2026-08" }));
}

// ── 2. Soft-deleted workspace receives nothing ───────────────────────────────
{
  const r = await emitManagedAlert(env, alert({ workspace_id: "ws_dead" }));
  eq("soft-deleted: not emitted", r.emitted, false);
  eq("soft-deleted: reason", r.reason, "workspace_deleted");
  eq("soft-deleted: no canonical event written", notifs("ws_dead").length, 0);
  ok("soft-deleted: suppression is terminal", ledger("ws_dead").every((d) => d.terminal === 1));
  ok("soft-deleted: nothing delivered", ledger("ws_dead").every((d) => d.outcome === "suppressed"));
}

// ── 3. Entitled workspace: full delivery ─────────────────────────────────────
{
  const r = await emitManagedAlert(env, alert());
  ok("entitled: emitted", r.emitted === true);
  eq("entitled: canonical event written once", notifs("ws_paid").length, 1);
  eq("entitled: event carries domain attribution", notifs("ws_paid")[0].domain_key, "certificates_trust");
  ok("entitled: domain_key is NOT the hostname field", notifs("ws_paid")[0].domain_key !== "www.example.com");
  const l = ledger("ws_paid");
  ok("entitled: in_app recorded delivered", l.some((d) => d.channel === "in_app" && d.outcome === "delivered"));
  ok("entitled: email recorded delivered", l.some((d) => d.channel === "email" && d.outcome === "delivered"));
  ok("entitled: email ledger counts recipients", l.some((d) => d.channel === "email" && d.recipient_count === 1));
  ok("entitled: ledger never stores recipient addresses",
     l.every((d) => !JSON.stringify(d).includes("paid@example.com")));
}

// ── 4. Dedupe is a DATABASE guarantee, not a read-then-write race ────────────
{
  const before = notifs("ws_paid").length;
  const dupe = await emitManagedAlert(env, alert());
  eq("dupe: not emitted", dupe.emitted, false);
  eq("dupe: reason", dupe.reason, "deduplicated");
  eq("dupe: no second canonical event", notifs("ws_paid").length, before);
  ok("dupe: suppression is terminal (never retried)", isTerminalReason("deduplicated"));

  // Concurrency: two simultaneous emits of the same event → exactly one event.
  const [x, y] = await Promise.all([
    emitManagedAlert(env, alert({ dedupe_key: "concurrent|key|1" })),
    emitManagedAlert(env, alert({ dedupe_key: "concurrent|key|1" })),
  ]);
  eq("concurrent identical alerts → exactly one emitted", [x.emitted, y.emitted].filter(Boolean).length, 1);
}

// ── 5. THE ENTITLEMENT RULE ──────────────────────────────────────────────────
// Free: the finding is still theirs; the PUSH is the paid feature.
{
  const r = await emitManagedAlert(env, alert({ workspace_id: "ws_free", dedupe_key: "free|cert|1" }));
  ok("free: canonical event IS still written", r.emitted === true && notifs("ws_free").length === 1);
  eq("free: reason", r.reason, "feature_not_entitled");
  const l = ledger("ws_free");
  ok("free: every outbound channel suppressed",
     MONITORING_CHANNELS.every((c) => l.some((d) => d.channel === c && d.outcome === "suppressed" && d.reason === "feature_not_entitled")));
  ok("free: nothing delivered outbound", !l.some((d) => d.channel !== "in_app" && d.outcome === "delivered"));
  ok("free: suppression is terminal (never retried)", l.filter((d) => d.reason === "feature_not_entitled").every((d) => d.terminal === 1));
  ok("free: NOT described as a customer preference",
     !l.some((d) => d.reason === "channel_disabled"));
}

// ── 6. No plan names in the alert engine (Pricing Lockstep safety) ───────────
{
  const src = fs.readFileSync(path.join(root, "workers", "scan-api", "src", "engines", "managed-alerts.js"), "utf8");
  const planNames = Object.keys(PLAN_FEATURES); // free, starter, professional, business, enterprise
  const leaked = planNames.filter((p) => new RegExp(`["'\`]${p}["'\`]`).test(src));
  eq("alert engine inlines no plan name", leaked, []);
  eq("alert engine uses the canonical entitlement key", ALERTS_FEATURE_KEY, "alerts");
  ok("'alerts' is a real declared feature key", Object.values(PLAN_FEATURES).some((f) => f.includes("alerts")));
}

// ── 7. THE PREFERENCE RULE: severity never overrides a disabled channel ──────
{
  db.prepare(`INSERT INTO notification_preferences (id, workspace_id, user_id, event_type, enabled, channel, created_at)
              VALUES ('np1', 'ws_paid', NULL, 'all', 0, 'email', datetime('now'))`).run();

  const r = await emitManagedAlert(env, alert({ severity: "critical", kind: "cert_expired", dedupe_key: "pref|crit|1" }));
  ok("disabled channel: canonical event still written", r.emitted === true);
  const l = ledger("ws_paid").filter((d) => d.dedupe_key === "pref|crit|1");
  ok("CRITICAL severity does NOT override a disabled email channel",
     l.some((d) => d.channel === "email" && d.outcome === "suppressed" && d.reason === "channel_disabled"));
  ok("disabled channel: no email delivered at critical severity",
     !l.some((d) => d.channel === "email" && d.outcome === "delivered"));
  ok("channel_disabled is terminal (never retried)", l.filter((d) => d.reason === "channel_disabled").every((d) => d.terminal === 1));
  ok("an unrelated channel stays enabled", l.some((d) => d.channel === "webhook" && d.outcome !== "suppressed"));

  // Structural: there is no severity escape hatch in the pipeline.
  // Strip comments first: the header comment deliberately QUOTES the forbidden
  // pattern to document why it does not exist, and that must not read as code.
  const code = fs.readFileSync(path.join(root, "workers", "scan-api", "src", "engines", "managed-alerts.js"), "utf8")
    .split("\n").filter((l) => !l.trim().startsWith("//")).join("\n");
  ok("no severity-based override exists in the emitter",
     !/severity\s*===\s*["'`]critical["'`]/.test(code));
}

// ── 8. Terminal vs retryable vocabulary ──────────────────────────────────────
{
  for (const r of ["feature_not_entitled", "channel_disabled", "no_verified_recipient",
                   "workspace_deleted", "deduplicated", "cooldown_active", "recipient_undeliverable"]) {
    ok(`${r} is terminal`, isTerminalReason(r) && !reasonIsRetryable(r));
  }
  for (const r of ["provider_rejected", "provider_unavailable", "recipient_lookup_failed"]) {
    ok(`${r} is retryable`, reasonIsRetryable(r) && !isTerminalReason(r));
  }
  ok("a hard/undeliverable recipient does NOT retry forever",
     isTerminalReason("recipient_undeliverable") && !reasonIsRetryable("recipient_undeliverable"));
  ok("an unknown reason fails closed (not retried)", !reasonIsRetryable("something_new"));
  eq("terminal and retryable vocabularies are disjoint",
     [...TERMINAL_REASONS].filter((r) => RETRYABLE_REASONS.has(r)), []);
}

// ── 9. Cooldown damps outbound but keeps the canonical history ───────────────
{
  const r = await emitManagedAlert(env, alert({ workspace_id: "ws_paid", kind: "cert_cooldown", dedupe_key: "cool|1", cooldownActive: true }));
  ok("cooldown: canonical event still recorded (history stays complete)", r.emitted === true);
  eq("cooldown: reason", r.reason, "cooldown_active");
  const l = ledger("ws_paid").filter((d) => d.dedupe_key === "cool|1");
  ok("cooldown: outbound suppressed", MONITORING_CHANNELS.every((c) => l.some((d) => d.channel === c && d.reason === "cooldown_active")));
  ok("cooldown: terminal for this alert", l.filter((d) => d.reason === "cooldown_active").every((d) => d.terminal === 1));
}

// ── 10. Ledger is append-only ────────────────────────────────────────────────
{
  const src = fs.readFileSync(path.join(root, "workers", "scan-api", "src", "engines", "managed-alerts.js"), "utf8");
  ok("emitter never UPDATEs the ledger", !/UPDATE\s+alert_deliveries/i.test(src));
  ok("emitter never DELETEs from the ledger", !/DELETE\s+FROM\s+alert_deliveries/i.test(src));
  ok("every ledger row carries an outcome", ledger("ws_paid").every((d) => Boolean(d.outcome)));
  ok("every suppression carries a reason", ledger("ws_paid").filter((d) => d.outcome === "suppressed").every((d) => Boolean(d.reason)));
}

// ── 11. Tenant isolation ─────────────────────────────────────────────────────
{
  ok("ws_free ledger contains only ws_free rows", ledger("ws_free").every((d) => d.workspace_id === "ws_free"));
  ok("ws_paid events contain only ws_paid rows", notifs("ws_paid").every((n) => n.workspace_id === "ws_paid"));
  ok("no cross-tenant notification leakage", notifs("ws_free").every((n) => n.workspace_id === "ws_free"));
}

// ── 12. Never throws ─────────────────────────────────────────────────────────
{
  const brokenEnv = { ...env, cybermeters_db: { prepare() { throw new Error("D1 down"); } } };
  const r = await emitManagedAlert(brokenEnv, alert({ dedupe_key: "broken|1" }));
  eq("a broken database never throws into the caller", r.emitted, false);
  eq("a broken database reports why", r.reason, "emit_failed");
}

globalThis.fetch = realFetch;
console.log(`\nmanaged-alerts: ${pass} passed, ${fail} failed`);
if (fail > 0) { console.error("managed-alerts validation FAILED"); process.exit(1); }
console.log("managed-alerts validation passed");
