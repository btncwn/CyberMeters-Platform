#!/usr/bin/env node
//
// Billing entitlement state-machine regression: getEffectivePlan (the canonical
// resolver every paid feature gate reads) must return the paid plan only while
// the subscription genuinely entitles it — active/trialing with an unexpired
// period, or past_due INSIDE the 7-day payment grace window — and fall back to
// 'free' the moment it doesn't (canceled, expired, past-grace, no row). Never
// silently removes paid access mid-grace; never keeps it after cancellation.
// Requires Node 24+ (node:sqlite). CI-blocking.
//
import fs from "node:fs";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const ent = await import(pathToFileURL(path.join(root, "workers", "scan-api", "src", "engines", "entitlements.js")).href);
const { getEffectivePlan, getPaymentGraceState } = ent;

let pass = 0, fail = 0;
const ok = (name, cond) => { cond ? pass++ : fail++; if (!cond) console.log("FAIL " + name); };

const db = new DatabaseSync(":memory:");
const apply = (p) => { try { db.exec(fs.readFileSync(p, "utf8")); } catch { /* ordering no-ops */ } };
apply(path.join(root, "database", "schema.sql"));
for (const f of fs.readdirSync(path.join(root, "database", "migrations")).filter((f) => f.endsWith(".sql")).sort()) {
  apply(path.join(root, "database", "migrations", f));
}
db.exec("PRAGMA foreign_keys = OFF");
const makeD1 = (db) => {
  const wrap = (sql, args) => ({ first: async () => db.prepare(sql).get(...args) ?? null, all: async () => ({ results: db.prepare(sql).all(...args) }), run: async () => { const r = db.prepare(sql).run(...args); return { meta: { changes: r.changes } }; } });
  return { prepare(sql) { const b = wrap(sql, []); b.bind = (...a) => wrap(sql, a); return b; } };
};
const env = { cybermeters_db: makeD1(db) };

const DAY = 24 * 60 * 60 * 1000;
const iso = (msFromNow) => new Date(Date.now() + msFromNow).toISOString();
let seq = 0;
// Seed one subscription row for a fresh user and return that userId.
function seedUser({ plan = "professional", status, period_end, failed_at = null, updated = 0 }) {
  const uid = `usr_${++seq}`;
  db.prepare(`INSERT INTO subscriptions
      (id, owner_user_id, workspace_id, plan, status, subscription_status, current_period_end, payment_failed_at, created_at, updated_at)
      VALUES (?, ?, ?, ?, 'active', ?, ?, ?, datetime('now'), ?)`)
    .run(`sub_${seq}`, uid, `ws_${seq}`, plan, status, period_end, failed_at, new Date(Date.now() + updated).toISOString());
  return uid;
}
const plan = (uid) => getEffectivePlan(uid, env);

// ── No subscription → free ───────────────────────────────────────────────────
ok("no subscription → free", await plan("usr_none") === "free");
ok("no user id → free", await getEffectivePlan(null, env) === "free");

// ── Active / trialing with a future period → the paid plan ───────────────────
ok("active + future period → professional", await plan(seedUser({ status: "active", period_end: iso(30 * DAY) })) === "professional");
ok("trialing + future period → the plan", await plan(seedUser({ plan: "starter", status: "trialing", period_end: iso(14 * DAY) })) === "starter");

// ── Active but the period has expired → free ─────────────────────────────────
ok("active but expired period → free", await plan(seedUser({ status: "active", period_end: iso(-1 * DAY) })) === "free");

// ── Past-due INSIDE the 7-day grace → keep paid; OUTSIDE → free ──────────────
const graceUid = seedUser({ status: "past_due", period_end: iso(10 * DAY), failed_at: iso(-2 * DAY) });
ok("past_due within grace (2d) → keeps paid plan", await plan(graceUid) === "professional");
ok("past_due beyond grace (10d) → free", await plan(seedUser({ status: "past_due", period_end: iso(10 * DAY), failed_at: iso(-10 * DAY) })) === "free");

// ── Canceled / other statuses → free ─────────────────────────────────────────
ok("canceled → free", await plan(seedUser({ status: "canceled", period_end: iso(30 * DAY) })) === "free");
ok("incomplete → free", await plan(seedUser({ status: "incomplete", period_end: iso(30 * DAY) })) === "free");
ok("unpaid → free", await plan(seedUser({ status: "unpaid", period_end: iso(30 * DAY) })) === "free");

// ── getPaymentGraceState boundaries (the grace window itself) ────────────────
ok("grace active for a recent failure", getPaymentGraceState({ subscription_status: "past_due", payment_failed_at: iso(-1 * DAY) }).active === true);
ok("grace expired past 7 days", getPaymentGraceState({ subscription_status: "past_due", payment_failed_at: iso(-8 * DAY) }).active === false);
ok("grace never active when not past_due", getPaymentGraceState({ subscription_status: "active", payment_failed_at: iso(-1 * DAY) }).active === false);
ok("grace inactive with no failure timestamp", getPaymentGraceState({ subscription_status: "past_due", payment_failed_at: null }).active === false);
ok("grace exposes an ends_at while active", typeof getPaymentGraceState({ subscription_status: "past_due", payment_failed_at: iso(-1 * DAY) }).ends_at === "string");

// ── Trial expiry is governed by trial_end and fails CLOSED ───────────────────
// Locally-provisioned trials carry trial_end but a NULL current_period_end;
// before the fix the resolver only checked current_period_end, so a 14-day
// trial granted its plan FOREVER. These cases pin the honest window.
function seedRow(uid, { plan = "professional", status, period_end = null, trial_end = null, stripe_id = null, ws = null, cancel_at_period_end = 0, updated = 0 }) {
  db.prepare(`INSERT INTO subscriptions
      (id, owner_user_id, workspace_id, plan, status, subscription_status, current_period_end, trial_end, stripe_subscription_id, cancel_at_period_end, created_at, updated_at)
      VALUES (?, ?, ?, ?, 'active', ?, ?, ?, ?, ?, datetime('now'), ?)`)
    .run(`sub_${++seq}`, uid, ws ?? `ws_${seq}`, plan, status, period_end, trial_end, stripe_id, cancel_at_period_end, new Date(Date.now() + updated).toISOString());
  return uid;
}
seedRow("usr_trial_live", { status: "trialing", trial_end: iso(7 * DAY) });
ok("trialing + future trial_end (NULL period) → the plan", await plan("usr_trial_live") === "professional");
seedRow("usr_trial_dead", { status: "trialing", trial_end: iso(-2 * DAY) });
ok("EXPIRED trial (NULL period) → free — the never-expiring-trial defect", await plan("usr_trial_dead") === "free");
seedRow("usr_trial_bare", { status: "trialing" });
ok("trialing with NO end date at all → free (fail closed)", await plan("usr_trial_bare") === "free");

// ── Duplicate rows resolve by explicit precedence, not row ordering ──────────
// The production shape F0 flagged: an owner holding a professional/trialing row
// AND a Stripe-bound starter/active row (different workspaces). The purchased
// plan governs — in BOTH orderings — and an expired trial never out-ranks it.
seedRow("usr_dup", { plan: "starter", status: "active", stripe_id: "sub_stripe_dup", ws: "ws_dup_a", updated: -3 * DAY });
seedRow("usr_dup", { plan: "professional", status: "trialing", trial_end: iso(-1 * DAY), ws: "ws_dup_b" });
ok("expired trial + older Stripe-bound active starter → starter", await plan("usr_dup") === "starter");
seedRow("usr_dup2", { plan: "professional", status: "trialing", trial_end: iso(7 * DAY), ws: "ws_dup2_b", updated: 0 });
seedRow("usr_dup2", { plan: "starter", status: "active", stripe_id: "sub_stripe_dup2", ws: "ws_dup2_a", updated: -3 * DAY });
ok("LIVE trial + active paid starter → the PURCHASED plan wins", await plan("usr_dup2") === "starter");

// ── Scheduled cancellation is not immediate cancellation ─────────────────────
seedRow("usr_cape", { status: "active", period_end: iso(20 * DAY), cancel_at_period_end: 1 });
ok("cancel_at_period_end + future period → keeps paid plan until period end", await plan("usr_cape") === "professional");
seedRow("usr_cape_done", { status: "active", period_end: iso(-1 * DAY), cancel_at_period_end: 1 });
ok("cancel_at_period_end + period passed → free", await plan("usr_cape_done") === "free");

// ── The latest row wins (cancel supersedes an older active row) ──────────────
const churnUid = `usr_churn`;
db.prepare(`INSERT INTO subscriptions (id, owner_user_id, workspace_id, plan, status, subscription_status, current_period_end, created_at, updated_at)
            VALUES ('sub_old', ?, 'ws_c', 'professional', 'active', 'active', ?, datetime('now'), ?)`).run(churnUid, iso(30 * DAY), new Date(Date.now() - 5 * DAY).toISOString());
db.prepare(`INSERT INTO subscriptions (id, owner_user_id, workspace_id, plan, status, subscription_status, current_period_end, created_at, updated_at)
            VALUES ('sub_new', ?, 'ws_c', 'professional', 'active', 'canceled', ?, datetime('now'), ?)`).run(churnUid, iso(30 * DAY), new Date().toISOString());
ok("newest subscription row wins (canceled after active → free)", await plan(churnUid) === "free");

console.log(`\nBilling lifecycle: ${pass}/${pass + fail} passed`);
if (fail) { console.error("billing-lifecycle validation FAILED"); process.exit(1); }
console.log("billing-lifecycle validation passed");
