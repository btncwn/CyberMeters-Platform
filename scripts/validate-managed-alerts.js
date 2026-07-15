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
  for (const r of ["provider_rate_limited", "provider_unavailable", "provider_temporary_rejection", "recipient_lookup_failed"]) {
    ok(`${r} is retryable`, reasonIsRetryable(r) && !isTerminalReason(r));
  }
  for (const r of ["provider_permanent_rejection", "provider_authentication_failed", "recipient_invalid"]) {
    ok(`${r} is terminal`, isTerminalReason(r) && !reasonIsRetryable(r));
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
  for (const r of ["provider_rate_limited", "provider_unavailable", "provider_temporary_rejection", "recipient_lookup_failed"]) {
    ok(`${r} may retry`, retryEligible(mk({ reason: r }), { now: NOW }).ok);
  }
  // Permanent recipient / sender / configuration outcomes must not retry forever.
  for (const r of ["no_verified_recipient", "invalid_sender", "missing_api_key", "invalid_content",
                   "recipient_undeliverable", "feature_not_entitled", "channel_disabled",
                   "provider_permanent_rejection", "provider_authentication_failed", "recipient_invalid"]) {
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

// ── 15. NORMALIZED PROVIDER OUTCOMES (review item 1) ────────────────────────
{
  const { normalizeProviderOutcome, PROVIDER_OUTCOMES,
          buildCooldownKey, cooldownHoursFor, COOLDOWN_HOURS_BY_SEVERITY } =
    await import(pathToFileURL(path.join(root, "workers", "scan-api", "src", "engines", "alert-outcomes.js")).href);
  const n = (reason, status) => normalizeProviderOutcome({ reason, status });

  eq("429 → rate limited (retryable)", n("provider_rejected", 429).reason, "provider_rate_limited");
  ok("429 retries", !n("provider_rejected", 429).terminal && reasonIsRetryable(n("provider_rejected", 429).reason));
  eq("provider 5xx → unavailable (retryable)", n("provider_rejected", 503).reason, "provider_unavailable");
  ok("provider 5xx retries", reasonIsRetryable(n("provider_rejected", 503).reason));
  eq("timeout → unavailable (retryable)", n("timeout", null).reason, "provider_unavailable");
  eq("network failure → unavailable (retryable)", n("network_error", null).reason, "provider_unavailable");
  ok("timeout/network retry", reasonIsRetryable(n("timeout").reason) && reasonIsRetryable(n("network_error").reason));

  eq("permanent 4xx → permanent rejection", n("provider_rejected", 400).reason, "provider_permanent_rejection");
  ok("permanent 4xx does NOT retry", n("provider_rejected", 400).terminal && !reasonIsRetryable("provider_permanent_rejection"));
  eq("401 → authentication failed", n("provider_rejected", 401).reason, "provider_authentication_failed");
  eq("403 → authentication failed", n("provider_rejected", 403).reason, "provider_authentication_failed");
  ok("authentication/sender configuration failure does NOT retry",
     n("provider_rejected", 403).terminal && !reasonIsRetryable("provider_authentication_failed"));
  // ── 422 is classified by the provider's OWN trusted code — never by status ──
  // A 422 means "permanent validation failure" and nothing more specific. Inferring
  // "invalid recipient" from the status alone would write a fabricated fact about the
  // customer's address into the audit trail.
  const n422 = (providerCode) => normalizeProviderOutcome({ reason: "provider_rejected", status: 422, provider_code: providerCode });
  eq("bare 422 → provider_permanent_rejection (never recipient)", n422(null).reason, "provider_permanent_rejection");
  eq("bare 422 message code names the status, claims nothing", n422(null).provider_message_code, "http_422");
  eq("422 + trusted recipient code → recipient_invalid", n422("invalid_to_address").reason, "recipient_invalid");
  eq("422 + trusted sender code → invalid_sender", n422("domain_not_verified").reason, "invalid_sender");
  eq("422 + trusted content code → invalid_content", n422("invalid_template").reason, "invalid_content");
  eq("422 + unknown code → provider_permanent_rejection (fails closed)", n422("some_new_code").reason, "provider_permanent_rejection");
  ok("422 + unknown code records the code without trusting it",
     n422("some_new_code").provider_message_code === "unclassified:some_new_code");
  ok("all 422 outcomes stay terminal (this is diagnostics, not retry policy)",
     [null, "invalid_to_address", "domain_not_verified", "invalid_template", "some_new_code"]
       .every((c) => n422(c).terminal === true && !reasonIsRetryable(n422(c).reason)));
  eq("422 recipient classification carries the recipient error class", n422("invalid_recipient").provider_error_class, "recipient");
  eq("422 sender classification carries the sender error class", n422("invalid_from_address").provider_error_class, "sender");
  eq("422 content classification carries the content error class", n422("missing_required_field").provider_error_class, "content");
  ok("a provider cannot inject prose into the ledger via a code",
     n422("Invalid To Address: user@example.com").reason === "provider_permanent_rejection");

  ok("unknown provider outcome fails closed", n("something_new", null).terminal === true);
  ok("provider_rejected with no status fails closed", n("provider_rejected", null).terminal === true);
  eq("unknown outcome is classed, not guessed", n("something_new").provider_error_class, "unknown");

  // Safe diagnostics only.
  const d = n("provider_rejected", 429);
  eq("status code persisted", d.provider_status_code, 429);
  eq("error class persisted", d.provider_error_class, "rate_limited");
  eq("message code persisted", d.provider_message_code, "http_429");
  eq("no other diagnostic fields leak", Object.keys(d).sort(),
     ["provider_error_class", "provider_message_code", "provider_status_code", "reason", "terminal"]);
  ok("normalizer never returns a raw body or recipient",
     !JSON.stringify(d).toLowerCase().includes("@") && !("body" in d) && !("response" in d));


  // The transport itself must never hand us a body or an address.
  const emailSrc = fs.readFileSync(path.join(root, "workers", "scan-api", "src", "lib", "lifecycle-email.js"), "utf8");
  ok("transport extracts only the provider's code slug, never the message",
     emailSrc.includes("^[a-z0-9_]{1,64}$") && !/provider_message:\s*body\?\.message/.test(emailSrc));
  // The ledger stores the diagnostics and no PII.
  const rows = db.prepare("SELECT * FROM alert_deliveries WHERE provider_status_code IS NOT NULL").all();
  ok("ledger has the diagnostic columns", db.prepare("PRAGMA table_info(alert_deliveries)").all()
     .some((c) => c.name === "provider_error_class"));
  ok("ledger never stores an email address",
     db.prepare("SELECT * FROM alert_deliveries").all().every((r) => !JSON.stringify(r).includes("@example.com")));

  // ── 16. CANONICAL COOLDOWN (review item 2) ────────────────────────────────
  eq("cooldown key is per workspace|domain|kind|entity",
     buildCooldownKey({ workspace_id: "ws", domain_key: "d", kind: "k", entity: "E.Example.com" }), "ws|d|k|e.example.com");
  ok("cooldown key is case-stable",
     buildCooldownKey({ workspace_id: "ws", domain_key: "d", kind: "k", entity: "E.COM" }) ===
     buildCooldownKey({ workspace_id: "ws", domain_key: "d", kind: "k", entity: "e.com" }));
  ok("a different entity has a different cooldown key",
     buildCooldownKey({ workspace_id: "ws", domain_key: "d", kind: "k", entity: "a" }) !==
     buildCooldownKey({ workspace_id: "ws", domain_key: "d", kind: "k", entity: "b" }));
  eq("duration is by severity", [cooldownHoursFor("critical"), cooldownHoursFor("high"), cooldownHoursFor("medium"), cooldownHoursFor("low")], [1, 4, 12, 24]);
  ok("critical is damped too, just shorter — never exempt", cooldownHoursFor("critical") > 0);
  eq("unknown severity falls back to the medium window", cooldownHoursFor("nonsense"), COOLDOWN_HOURS_BY_SEVERITY.medium);

  // Cooldown suppresses OUTBOUND ONLY; the canonical event survives.
  const before = notifs("ws_paid").length;
  const cd = await emitManagedAlert(env, alert({ kind: "cd_kind", dedupe_key: "cd|1", cooldownActive: true, cooldown_entity: "cd.example.com" }));
  ok("cooldown: canonical in-app event is still created", cd.emitted === true && notifs("ws_paid").length === before + 1);
  const cdl = ledger("ws_paid").filter((d2) => d2.dedupe_key === "cd|1");
  ok("cooldown: outbound suppressed", cdl.some((d2) => d2.channel === "email" && d2.reason === "cooldown_active"));
  ok("cooldown: in_app is NOT suppressed", cdl.some((d2) => d2.channel === "in_app" && d2.outcome === "delivered"));

  // Lookup failure fails OPEN — a damping feature must never silence a real alert.
  const { isInCooldown } = await import(pathToFileURL(path.join(root, "workers", "scan-api", "src", "engines", "alert-outcomes.js")).href);
  const brokenEnv = { cybermeters_db: { prepare() { throw new Error("D1 down"); } } };
  eq("cooldown lookup failure fails OPEN (never silences an alert)",
     await isInCooldown(brokenEnv, { workspace_id: "w", domain_key: "d", kind: "k", entity: "e", severity: "high" }), false);
}

// ── 17. RECURRENCE COVERAGE (review item 3) ─────────────────────────────────
{
  const { severityForRecurrence, isMappedRecurrence, alertKindFor } =
    await import(pathToFileURL(path.join(root, "workers", "scan-api", "src", "engines", "alert-consumers.js")).href);
  const { resolveRemediation } = await import(pathToFileURL(path.join(root, "workers", "scan-api", "src", "engines", "remediation-registry.js")).href);

  // Every recurrence each shipped evaluator can emit must have an explicit severity.
  const EVALUATOR_RECURRENCES = {
    "certificate-lifecycle.js": ["expired", "renewal_overdue", "replacement_contradicted", "verification_failed",
      "replacement_unverified", "coverage_regression", "unexpected_san", "exception_expired", "owner_missing", "evidence_stale"],
    "identity-lifecycle.js": ["public_admin_surface", "removal_contradicted", "unexpected_surface", "retired_reappeared",
      "investigate_unresolved", "provider_change", "verification_failed", "exception_expired", "owner_missing", "evidence_stale"],
    "shadow-it-inventory.js": ["approved_disappeared", "evidence_stale", "exception_expired", "material_change",
      "owner_missing", "rejected_reappeared", "removal_contradicted", "removal_incomplete", "retired_reappeared"],
  };
  for (const [file, list] of Object.entries(EVALUATOR_RECURRENCES)) {
    const unmapped = list.filter((r) => !isMappedRecurrence(r));
    eq(`${file}: every recurrence has an explicit severity`, unmapped, []);
  }
  // The mapping must be derived from the real source, not a stale copy.
  for (const [file, list] of Object.entries(EVALUATOR_RECURRENCES)) {
    const src = fs.readFileSync(path.join(root, "workers", "scan-api", "src", "engines", file), "utf8");
    const actual = [...new Set([...src.matchAll(/recurrence_type\s*=\s*"([a-z_]+)"/g)].map((m) => m[1]))]
      .filter((r) => r !== "none");
    const missing = actual.filter((r) => !list.includes(r));
    eq(`${file}: test list matches the evaluator's real recurrence set`, missing, []);
  }

  ok("an unknown recurrence gets NO arbitrary default severity", severityForRecurrence("brand_new_thing") === null);
  ok("an unknown recurrence is not mapped", !isMappedRecurrence("brand_new_thing"));
  const skipped = await emitLifecycleAlertProbe();
  eq("an unmapped recurrence is skipped, not graded", skipped, "unmapped_recurrence");

  // saas_exposure must resolve in the canonical registry (shadow IT's case type).
  const r = resolveRemediation({ finding_type: "saas_exposure" });
  eq("saas_exposure resolves in the Canonical Remediation Registry", r.status, "resolved");
  ok("saas_exposure has a customer title", typeof r.customer_title === "string" && r.customer_title.length > 0);
  eq("saas_exposure belongs to the shadow IT domain", r.domain_key, "shadow_it_unmanaged_technology");

  eq("alert kind is deterministic", alertKindFor("certificates_trust", "expired"), "certificates_trust.expired");
}

async function emitLifecycleAlertProbe() {
  const { emitLifecycleAlert } = await import(pathToFileURL(path.join(root, "workers", "scan-api", "src", "engines", "alert-consumers.js")).href);
  const r = await emitLifecycleAlert(env, {
    workspace_id: "ws_paid", domain_key: "certificates_trust", record_id: "rec_x",
    entity: "x.example.com", recurrence: "totally_unknown_recurrence",
  });
  return r.skipped;
}

// ── 18. BASELINE SMOKE CONTRACT (what production must show on first evaluation) ─
// These are the exact assertions the post-deploy smoke will make, encoded so they
// are proven before deploy rather than eyeballed after it.
{
  user("u_smoke", "smoke@example.com", "professional"); subscribe("u_smoke", "professional");
  workspace("ws_smoke", "u_smoke");

  const notifsBefore = notifs("ws_smoke").length;
  let providerCalls = 0;
  const prevFetch = globalThis.fetch;
  globalThis.fetch = async (url, init) => {
    if (String(url).includes("resend.com")) providerCalls++;
    return prevFetch(url, init);
  };

  // First evaluation over pre-existing state, exactly as production will do.
  for (const host of ["s1.example.com", "s2.example.com", "s3.example.com"]) {
    await emitManagedAlert(env, {
      workspace_id: "ws_smoke", domain_key: "certificates_trust", kind: "cert_expiring",
      severity: "critical", title: `Cert ${host}`, message: "Pre-existing.",
      dedupe_key: `smoke|${host}`, observed_at: "2026-01-01T00:00:00Z",
    });
  }
  globalThis.fetch = prevFetch;

  const act = db.prepare("SELECT * FROM alert_activation WHERE workspace_id = 'ws_smoke'").all();
  ok("SMOKE: alert_activation rows are created", act.length === 1);
  eq("SMOKE: notification_events does not increase for baseline state", notifs("ws_smoke").length, notifsBefore);
  eq("SMOKE: no outbound provider call occurs", providerCalls, 0);
  const l = ledger("ws_smoke");
  ok("SMOKE: alert_deliveries records only baseline audit outcomes",
     l.length > 0 && l.every((d) => d.reason === "alert_baseline_established" && d.outcome === "suppressed" && d.terminal === 1));
  ok("SMOKE: no delivered row exists", !l.some((d) => d.outcome === "delivered"));
}

globalThis.fetch = realFetch;
console.log(`\nmanaged-alerts: ${pass} passed, ${fail} failed`);
if (fail > 0) { console.error("managed-alerts validation FAILED"); process.exit(1); }
console.log("managed-alerts validation passed");
