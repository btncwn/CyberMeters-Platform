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
  ensureAlertActivation, observationIsAfterWatermark,
  retryFailedAlertDeliveries, retryEligible, retryBackoffHours,
  RETRY_MAX_ATTEMPTS, RETRY_MAX_AGE_HOURS,
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
const WATERMARK = "2020-01-01T00:00:00Z";        // baseline established long ago
const OBSERVED_AFTER = "2026-07-15T00:00:00Z";   // a change observed after it

// Pre-activate: these sections test DELIVERY, not the baseline. The baseline
// itself is proved in its own section below, on a workspace that has never
// been activated.
async function preActivate(ws, domainKey = "certificates_trust") {
  await ensureAlertActivation(env, ws, domainKey, { now: WATERMARK });
}

const alert = (over = {}) => ({
  workspace_id: "ws_paid", domain_key: "certificates_trust", kind: "cert_expiring",
  severity: "high", title: "Certificate expiring", message: "Renew it.",
  observed_at: OBSERVED_AFTER,
  dedupe_key: buildAlertDedupeKey({ domain_key: "certificates_trust", kind: "cert_expiring", subject: "www.example.com" }),
  ...over,
});

await preActivate("ws_paid");
await preActivate("ws_free");
await preActivate("ws_dead");

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

// ── 13. FIRST-RUN FLOOD PREVENTION (the activation watermark) ────────────────
// Wiring alerts onto the shipped evaluators fires them over rows that ALREADY
// exist. This section proves the backlog stays silent.
{
  user("u_fresh", "fresh@example.com", "professional"); subscribe("u_fresh", "professional");
  workspace("ws_fresh", "u_fresh");

  // Simulate the first evaluation after deploy: 5 pre-existing lifecycle rows,
  // each carrying recurrence_type computed long before alerting existed.
  const backlog = ["a.example.com", "b.example.com", "c.example.com", "d.example.com", "e.example.com"];
  const first = [];
  for (const host of backlog) {
    first.push(await emitManagedAlert(env, {
      workspace_id: "ws_fresh", domain_key: "certificates_trust", kind: "cert_expiring",
      severity: "critical", title: `Certificate expiring: ${host}`, message: "Pre-existing state.",
      dedupe_key: buildAlertDedupeKey({ domain_key: "certificates_trust", kind: "cert_expiring", subject: host }),
      observed_at: "2026-01-01T00:00:00Z",   // observed BEFORE activation
    }));
  }

  ok("first run: nothing emitted", first.every((r) => r.emitted === false));
  ok("first run: every suppression is the baseline", first.every((r) => r.reason === "alert_baseline_established"));
  eq("first run: ZERO bell notifications created", notifs("ws_fresh").length, 0);
  eq("first run: ZERO outbound deliveries", ledger("ws_fresh").filter((d) => d.outcome === "delivered").length, 0);
  ok("first run: baseline rows are terminal (never enqueued for retry)",
     ledger("ws_fresh").every((d) => d.terminal === 1 && d.outcome === "suppressed"));
  ok("baseline reason is terminal, not retryable",
     isTerminalReason("alert_baseline_established") && !reasonIsRetryable("alert_baseline_established"));

  // Activation is established exactly once, and is idempotent + tenant-scoped.
  const act = db.prepare("SELECT * FROM alert_activation WHERE workspace_id = 'ws_fresh'").all();
  eq("activation established exactly once for the domain", act.length, 1);
  eq("activation is tenant-scoped", act[0].workspace_id, "ws_fresh");
  eq("activation is per-domain", act[0].domain_key, "certificates_trust");

  const again = await ensureAlertActivation(env, "ws_fresh", "certificates_trust");
  ok("re-activation is idempotent (never re-baselines)", again.established_now === false);
  eq("re-activation does not duplicate the row",
     db.prepare("SELECT COUNT(*) c FROM alert_activation WHERE workspace_id = 'ws_fresh'").get().c, 1);
  const concurrent = await Promise.all([
    ensureAlertActivation(env, "ws_fresh", "identity_exposure"),
    ensureAlertActivation(env, "ws_fresh", "identity_exposure"),
  ]);
  eq("concurrent activation establishes exactly once", concurrent.filter((a) => a.established_now).length, 1);

  // A change observed AFTER the watermark is genuine news and alerts normally.
  const fresh = await emitManagedAlert(env, {
    workspace_id: "ws_fresh", domain_key: "certificates_trust", kind: "cert_expiring",
    severity: "high", title: "Certificate expiring: new.example.com", message: "This changed after activation.",
    dedupe_key: "fresh|after|1", observed_at: "2030-01-01T00:00:00Z",
  });
  ok("a change after the watermark DOES alert", fresh.emitted === true && fresh.reason === null);
  eq("post-watermark alert creates exactly one bell notification", notifs("ws_fresh").length, 1);

  // A late-arriving pre-watermark observation stays suppressed forever.
  const late = await emitManagedAlert(env, {
    workspace_id: "ws_fresh", domain_key: "certificates_trust", kind: "cert_expiring",
    severity: "critical", title: "Old news", message: "Observed before activation.",
    dedupe_key: "fresh|late|1", observed_at: "2019-01-01T00:00:00Z",
  });
  eq("a pre-watermark observation never alerts, even at critical", late.reason, "alert_baseline_established");
  eq("pre-watermark observation creates no bell notification", notifs("ws_fresh").length, 1);

  // Watermark predicate, directly.
  ok("watermark: after → allowed", observationIsAfterWatermark("2026-02-01T00:00:00Z", "2026-01-01T00:00:00Z"));
  ok("watermark: before → blocked", !observationIsAfterWatermark("2025-12-01T00:00:00Z", "2026-01-01T00:00:00Z"));
  ok("watermark: exactly at the mark → blocked (pre-existing, not news)",
     !observationIsAfterWatermark("2026-01-01T00:00:00Z", "2026-01-01T00:00:00Z"));
  ok("watermark: unparseable timestamp fails closed", !observationIsAfterWatermark("not-a-date", "2026-01-01T00:00:00Z"));
  ok("watermark: no observed_at → caller asserts it just happened", observationIsAfterWatermark(null, "2026-01-01T00:00:00Z"));


  // ── The second-run flood ───────────────────────────────────────────────────
  // The evaluators refresh `evaluated_at` on every pass. A consumer that passed
  // the EVALUATION time as observed_at would clear the watermark on run 2 and
  // release the whole backlog — the baseline would only have delayed the flood.
  // A pre-existing condition must stay silent across repeated evaluations.
  const CONDITION_SEEN = "2026-01-01T00:00:00Z";   // stable: first_seen_at / last_changed_at
  const runs = [];
  for (let pass = 0; pass < 3; pass++) {
    runs.push(await emitManagedAlert(env, {
      workspace_id: "ws_fresh", domain_key: "certificates_trust", kind: "cert_expiring",
      severity: "critical", title: "Backlog cert", message: "Still overdue.",
      dedupe_key: buildAlertDedupeKey({ domain_key: "certificates_trust", kind: "cert_expiring", subject: "backlog.example.com" }),
      observed_at: CONDITION_SEEN,   // the CONDITION's own timestamp, not evaluated_at
    }));
  }
  ok("re-evaluating a pre-existing condition never alerts (no second-run flood)",
     runs.every((r) => r.emitted === false && r.reason === "alert_baseline_established"));
  ok("re-evaluation creates no bell notification for backlog",
     !notifs("ws_fresh").some((n) => n.title === "Backlog cert"));

  // The trap itself: had the consumer passed the evaluation time, this WOULD alert.
  // Documenting it as an executable warning rather than prose.
  const wouldFlood = observationIsAfterWatermark(new Date().toISOString(), WATERMARK);
  ok("passing evaluated_at/now WOULD defeat the watermark (why consumers must not)", wouldFlood === true);

  // Baseline must not leak across tenants.
  ok("another tenant's activation does not baseline this one",
     db.prepare("SELECT COUNT(*) c FROM alert_activation WHERE workspace_id = 'ws_paid'").get().c >= 1);
  ok("ws_fresh ledger contains only ws_fresh rows", ledger("ws_fresh").every((d) => d.workspace_id === "ws_fresh"));
}

// ── 14. BOUNDED RETRY SWEEP ─────────────────────────────────────────────────
{
  const NOW = "2026-08-01T12:00:00Z";
  const mk = (over = {}) => ({
    id: "ad_x", workspace_id: "ws_paid", notification_id: "notif_x", channel: "email",
    alert_kind: "cert_expiring", outcome: "failed", reason: "provider_unavailable",
    terminal: 0, attempt: 1, created_at: "2026-08-01T00:00:00Z", ...over,
  });

  // Eligibility gates
  ok("terminal rows are never retried", !retryEligible(mk({ terminal: 1 }), { now: NOW }).ok);
  ok("delivered rows are never retried", !retryEligible(mk({ outcome: "delivered" }), { now: NOW }).ok);
  eq("permanent reason stops", retryEligible(mk({ reason: "no_verified_recipient" }), { now: NOW }).reason, "permanent_reason");
  eq("unknown reason fails closed", retryEligible(mk({ reason: "who_knows" }), { now: NOW }).reason, "permanent_reason");
  eq("max attempts stops", retryEligible(mk({ attempt: RETRY_MAX_ATTEMPTS }), { now: NOW }).reason, "max_attempts");
  eq("max age stops", retryEligible(mk({ created_at: "2026-01-01T00:00:00Z" }), { now: NOW }).reason, "max_age");
  ok("a transient failure past backoff is eligible", retryEligible(mk(), { now: NOW }).ok);
  eq("inside backoff waits", retryEligible(mk({ created_at: "2026-08-01T11:30:00Z" }), { now: NOW }).reason, "backoff");

  // Which provider outcomes may retry
  for (const r of ["provider_rejected", "provider_unavailable", "recipient_lookup_failed"]) {
    ok(`${r} may retry`, retryEligible(mk({ reason: r }), { now: NOW }).ok);
  }
  // Permanent recipient / sender / configuration outcomes must not retry forever.
  for (const r of ["no_verified_recipient", "invalid_sender", "missing_api_key", "invalid_content",
                   "recipient_undeliverable", "feature_not_entitled", "channel_disabled"]) {
    ok(`${r} must not retry forever`, !retryEligible(mk({ reason: r }), { now: NOW }).ok && isTerminalReason(r));
  }

  // Deterministic backoff
  eq("backoff is deterministic 2^n hours", [1, 2, 3].map(retryBackoffHours), [2, 4, 8]);

  // A real sweep, append-only.
  db.prepare(`INSERT INTO notification_events (id, workspace_id, type, severity, title, message, status, created_at)
              VALUES ('notif_retry','ws_paid','cert_expiring','high','Retry me','Body','unread', datetime('now'))`).run();
  const seedFailed = (over = {}) => {
    const id = `ad_${Math.random().toString(36).slice(2, 9)}`;
    db.prepare(`INSERT INTO alert_deliveries (id, workspace_id, notification_id, domain_key, alert_kind, channel, outcome, reason, terminal, attempt, created_at)
                VALUES (?, 'ws_paid', 'notif_retry', 'certificates_trust', 'cert_expiring', 'email', 'failed', ?, 0, ?, ?)`)
      .run(id, over.reason || "provider_unavailable", over.attempt || 1, over.created_at || "2026-08-01T00:00:00Z");
    return id;
  };

  // Preference is currently DISABLED for email on ws_paid (set in section 7):
  // a retry must respect that rather than resurrect a suppressed alert.
  seedFailed();
  const before = db.prepare("SELECT COUNT(*) c FROM alert_deliveries").get().c;
  const r1 = await retryFailedAlertDeliveries(env, { now: NOW });
  const after = db.prepare("SELECT COUNT(*) c FROM alert_deliveries").get().c;
  ok("retry re-checks preferences and suppresses safely", r1.terminated >= 1 && r1.delivered === 0);
  ok("retry appends attempts (never updates in place)", after > before);
  ok("suppressed retry is recorded terminal",
     db.prepare("SELECT * FROM alert_deliveries WHERE reason='channel_disabled' AND attempt > 1").all().length >= 1);

  // Re-enable email, then a retry may deliver — once.
  db.prepare("UPDATE notification_preferences SET enabled = 1 WHERE workspace_id='ws_paid' AND channel='email'").run();
  seedFailed();
  const r2 = await retryFailedAlertDeliveries(env, { now: NOW });
  ok("an eligible retry delivers once preferences allow", r2.delivered >= 1);

  // Never resend after success: the delivered row above must stop further retries.
  const r3 = await retryFailedAlertDeliveries(env, { now: NOW });
  ok("a delivered alert is never resent", r3.delivered === 0);

  // Entitlement lost between failure and retry.
  db.prepare("UPDATE subscriptions SET subscription_status='canceled', status='canceled' WHERE owner_user_id='u_paid'").run();
  // A DISTINCT notification: the one above is already delivered, so it would
  // short-circuit at the never-resend guard before reaching the entitlement gate.
  db.prepare(`INSERT INTO notification_events (id, workspace_id, type, severity, title, message, status, created_at)
              VALUES ('notif_ent','ws_paid','cert_expiring','high','Ent','Body','unread', datetime('now'))`).run();
  db.prepare(`INSERT INTO alert_deliveries (id, workspace_id, notification_id, domain_key, alert_kind, channel, outcome, reason, terminal, attempt, created_at)
              VALUES ('ad_ent','ws_paid','notif_ent','certificates_trust','cert_expiring','email','failed','provider_unavailable',0,1,'2026-08-01T01:00:00Z')`).run();
  const r4 = await retryFailedAlertDeliveries(env, { now: NOW });
  ok("entitlement lost before retry suppresses safely",
     db.prepare("SELECT * FROM alert_deliveries WHERE reason='feature_not_entitled' AND attempt > 1").all().length >= 1 || r4.terminated >= 1);

  // Bounded batch.
  ok("sweep is bounded by LIMIT", (await retryFailedAlertDeliveries(env, { now: NOW, limit: 1 })).examined <= 1);
  ok("ledger rows are never updated in place",
     !fs.readFileSync(path.join(root, "workers", "scan-api", "src", "engines", "managed-alerts.js"), "utf8")
       .split("\n").filter((l) => !l.trim().startsWith("//")).join("\n").includes("UPDATE alert_deliveries"));
}

globalThis.fetch = realFetch;
console.log(`\nmanaged-alerts: ${pass} passed, ${fail} failed`);
if (fail > 0) { console.error("managed-alerts validation FAILED"); process.exit(1); }
console.log("managed-alerts validation passed");
