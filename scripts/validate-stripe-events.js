#!/usr/bin/env node
//
// Stripe webhook event-type coverage: each signed event must drive the
// subscriptions row to the correct state — created/updated → active with the
// price's plan, invoice.payment_failed → past_due, subscription.updated →
// restored active, subscription.deleted → canceled — and an invalid signature is
// rejected 400 before any state change. Idempotency/replay is covered separately
// in validate-pipeline.js; here the focus is per-event-type state. Requires
// Node 24+ (node:sqlite). CI-blocking.
//
import fs from "node:fs";
import path from "node:path";
import { webcrypto } from "node:crypto";
import { DatabaseSync } from "node:sqlite";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const workerPath = path.join(root, "workers", "scan-api", "src", "index.js");

let pass = 0, fail = 0;
const ok = (name, cond) => { cond ? pass++ : fail++; if (!cond) console.log("FAIL " + name); };

globalThis.fetch = async () => { throw new Error("network disabled"); };
AbortSignal.timeout = () => undefined;
const worker = await import(pathToFileURL(workerPath).href);

function buildDb() {
  const db = new DatabaseSync(":memory:");
  const apply = (p) => { try { db.exec(fs.readFileSync(p, "utf8")); } catch { /* ordering no-ops */ } };
  apply(path.join(root, "database", "schema.sql"));
  for (const f of fs.readdirSync(path.join(root, "database", "migrations")).filter((f) => f.endsWith(".sql")).sort()) {
    apply(path.join(root, "database", "migrations", f));
  }
  db.exec("PRAGMA foreign_keys = OFF");
  return db;
}
function makeD1(db) {
  const wrap = (sql, args) => ({
    first: async () => db.prepare(sql).get(...args) ?? null,
    all: async () => ({ results: db.prepare(sql).all(...args) }),
    run: async () => { const r = db.prepare(sql).run(...args); return { meta: { changes: r.changes, last_row_id: 0 } }; },
  });
  return { prepare(sql) { const b = wrap(sql, []); b.bind = (...a) => wrap(sql, a); return b; }, async batch(s) { return Promise.all(s.map((x) => (/^\s*select/i.test(x.__sql) ? x.all() : x.run()))); } };
}

const WHSEC = "whsec_test_secret";
const db = buildDb();
const env = {
  cybermeters_db: makeD1(db),
  cybermeters_reports: { get: async () => null, put: async () => ({}), head: async () => null, delete: async () => ({}), list: async () => ({ objects: [] }) },
  STRIPE_WEBHOOK_SECRET: WHSEC, STRIPE_SECRET_KEY: "sk_test_x",
  STRIPE_PRICE_MAP: JSON.stringify({ starter_monthly: "price_sm", professional_monthly: "price_pm", business_monthly: "price_bm" }),
  ALLOWED_ORIGIN: "https://app.cybermeters.com", APP_VERSION: "test",
};
const ctx = { waitUntil: () => {}, passThroughOnException: () => {} };

// Independent HMAC-SHA256 hex — forges Stripe-Signature the way Stripe does.
async function hmacHex(secret, message) {
  const key = await webcrypto.subtle.importKey("raw", new TextEncoder().encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const sig = await webcrypto.subtle.sign("HMAC", key, new TextEncoder().encode(message));
  return [...new Uint8Array(sig)].map((b) => b.toString(16).padStart(2, "0")).join("");
}
async function postWebhook(event, { secret = WHSEC } = {}) {
  const raw = JSON.stringify(event);
  const ts = Math.floor(Date.now() / 1000); // near-current — Stripe verifies the ts is within tolerance
  const sig = await hmacHex(secret, `${ts}.${raw}`);
  const res = await worker.default.fetch(new Request("https://app.cybermeters.com/api/billing/webhook", {
    method: "POST", headers: { "Content-Type": "application/json", "Stripe-Signature": `t=${ts},v1=${sig}` }, body: raw,
  }), env, ctx);
  let body = {}; try { body = await res.json(); } catch { /* */ }
  return { status: res.status, body };
}

const UID = "usr_stripe", WS = "ws_stripe", CUS = "cus_1", SUB = "sub_1";
const nowUnix = Math.floor(Date.now() / 1000);
const futureUnix = nowUnix + 30 * 86400;
const meta = { user_id: UID, workspace_id: WS, plan: "professional", interval: "monthly" };
const subObj = (status, priceId = "price_pm") => ({
  id: SUB, customer: CUS, status, metadata: meta,
  items: { data: [{ price: { id: priceId } }] },
  current_period_start: nowUnix, current_period_end: futureUnix,
});
const evt = (id, type, object) => ({ id, type, data: { object } });
const rowStatus = () => db.prepare("SELECT subscription_status, status, plan, current_period_end FROM subscriptions WHERE owner_user_id = ? ORDER BY updated_at DESC LIMIT 1").get(UID);
const isoOf = (unix) => new Date(unix * 1000).toISOString();
// Lockstep invariant: the legacy `status` column must equal subscription_status
// on every row a webhook has touched — divergence misled a prod D1 read on
// 21 Jul 2026 (June trial row kept status='trialing' after paid checkout).
const divergentRows = () =>
  db.prepare("SELECT COUNT(*) AS n FROM subscriptions WHERE subscription_status IS NOT NULL AND status != subscription_status").get().n;

// ── Invalid signature is rejected before any state change ────────────────────
const bad = await postWebhook(evt("evt_bad", "customer.subscription.created", subObj("active")), { secret: "whsec_WRONG" });
ok("invalid signature → 400", bad.status === 400);
ok("invalid signature wrote nothing", rowStatus() === undefined);

// ── customer.subscription.created → active + plan from the price ─────────────
const created = await postWebhook(evt("evt_1", "customer.subscription.created", subObj("active")));
ok("created accepted (2xx)", created.status >= 200 && created.status < 300);
ok("created → subscription_status active", rowStatus()?.subscription_status === "active");
ok("created → legacy status column in lockstep (active)", rowStatus()?.status === "active");
ok("created → current_period_end persisted from the Stripe object", rowStatus()?.current_period_end === isoOf(futureUnix));
ok("created → plan resolved from price_pm (professional)", rowStatus()?.plan === "professional");

// ── customer.subscription.updated → plan change (price_bm = business) ────────
const updated = await postWebhook(evt("evt_2", "customer.subscription.updated", subObj("active", "price_bm")));
ok("updated accepted", updated.status >= 200 && updated.status < 300);
ok("updated → plan changed to business", rowStatus()?.plan === "business");
ok("updated → still active", rowStatus()?.subscription_status === "active");

// ── invoice.payment_failed → past_due ────────────────────────────────────────
const failed = await postWebhook(evt("evt_3", "invoice.payment_failed", { id: "in_1", customer: CUS, subscription: SUB, attempt_count: 1 }));
ok("payment_failed accepted", failed.status >= 200 && failed.status < 300);
ok("payment_failed → subscription_status past_due", rowStatus()?.subscription_status === "past_due");
ok("payment_failed → legacy status in lockstep (past_due)", rowStatus()?.status === "past_due");

// ── invoice.payment_succeeded → past_due cleared, both columns together ──────
const succeeded = await postWebhook(evt("evt_3b", "invoice.payment_succeeded", { id: "in_2", customer: CUS, subscription: SUB }));
ok("payment_succeeded accepted", succeeded.status >= 200 && succeeded.status < 300);
ok("payment_succeeded → subscription_status restored active", rowStatus()?.subscription_status === "active");
ok("payment_succeeded → legacy status in lockstep (active)", rowStatus()?.status === "active");

// ── customer.subscription.updated (active) → restores active ─────────────────
await postWebhook(evt("evt_4", "customer.subscription.updated", subObj("active", "price_bm")));
ok("subsequent active update restores active", rowStatus()?.subscription_status === "active");

// ── customer.subscription.deleted → canceled (row retained) ─────────────────
const deleted = await postWebhook(evt("evt_5", "customer.subscription.deleted", { id: SUB, customer: CUS, status: "canceled", metadata: meta, current_period_end: futureUnix }));
ok("deleted accepted", deleted.status >= 200 && deleted.status < 300);
ok("deleted → subscription_status canceled", rowStatus()?.subscription_status === "canceled");
ok("deleted → legacy status in lockstep (canceled)", rowStatus()?.status === "canceled");
ok("deleted retains the row (historical record)", rowStatus() !== undefined);

// ── Unknown price fails CLOSED — the metadata plan claim never wins ──────────
const UID2 = "usr_stripe2", WS2 = "ws_stripe2", CUS2 = "cus_2", SUB2 = "sub_2";
const meta2 = { user_id: UID2, workspace_id: WS2, plan: "business", interval: "monthly" };
const subObj2 = (status, priceId, extraItems = []) => ({
  id: SUB2, customer: CUS2, status, metadata: meta2,
  items: { data: [...extraItems, { price: { id: priceId } }] },
  current_period_start: nowUnix, current_period_end: futureUnix,
});
const rowStatus2 = () => db.prepare("SELECT subscription_status, plan, current_period_end FROM subscriptions WHERE owner_user_id = ? ORDER BY updated_at DESC LIMIT 1").get(UID2);

await postWebhook(evt("evt_6", "customer.subscription.created", subObj2("active", "price_sm")));
ok("second subscription created as starter", rowStatus2()?.plan === "starter");
const unknown = await postWebhook(evt("evt_7", "customer.subscription.updated", subObj2("active", "price_UNKNOWN")));
ok("unknown-price event acknowledged (Stripe must not retry forever)", unknown.status >= 200 && unknown.status < 300);
ok("unknown price did NOT grant the metadata plan (business)", rowStatus2()?.plan === "starter");
ok("unknown price still applied lifecycle status", rowStatus2()?.subscription_status === "active");

// ── Multi-item subscription: the BASE item maps the plan, not items[0] ───────
await postWebhook(evt("evt_8", "customer.subscription.updated",
  subObj2("active", "price_pm", [{ price: { id: "price_overage_addon" } }])));
ok("multi-item: plan resolved from the mapped base item (professional)", rowStatus2()?.plan === "professional");

// ── Out-of-order delivery: current_period_end never moves backward ───────────
const laterUnix = futureUnix + 30 * 86400;
await postWebhook(evt("evt_9", "customer.subscription.updated", { ...subObj2("active", "price_pm"), current_period_end: laterUnix }));
const advanced = rowStatus2()?.current_period_end;
await postWebhook(evt("evt_10", "customer.subscription.updated", { ...subObj2("active", "price_pm"), current_period_end: futureUnix }));
ok("stale event cannot shorten the entitlement window", rowStatus2()?.current_period_end === advanced);

// ── Basil-era payload (Stripe API 2025-03-31+): current_period_* lives on the
//    subscription ITEMS, not the subscription object. The prod defect: these
//    payloads persisted current_period_end = NULL (21 Jul 2026 B2/B3 evidence).
const UID3 = "usr_stripe3", WS3 = "ws_stripe3", CUS3 = "cus_3", SUB3 = "sub_3";
const meta3 = { user_id: UID3, workspace_id: WS3, plan: "professional", interval: "monthly" };
const rowStatus3 = () => db.prepare("SELECT subscription_status, status, plan, current_period_start, current_period_end FROM subscriptions WHERE owner_user_id = ? ORDER BY updated_at DESC LIMIT 1").get(UID3);
const basilSub = (status, itemPeriodEnd, extraItems = []) => ({
  id: SUB3, customer: CUS3, status, metadata: meta3,
  // No top-level current_period_start / current_period_end — Basil shape.
  items: { data: [...extraItems, { price: { id: "price_pm" }, current_period_start: nowUnix, current_period_end: itemPeriodEnd }] },
});
await postWebhook(evt("evt_11", "customer.subscription.created", basilSub("active", futureUnix)));
ok("Basil payload → current_period_end captured from the subscription item", rowStatus3()?.current_period_end === isoOf(futureUnix));
ok("Basil payload → current_period_start captured from the subscription item", rowStatus3()?.current_period_start === isoOf(nowUnix));
ok("Basil payload → status columns in lockstep (active)", rowStatus3()?.subscription_status === "active" && rowStatus3()?.status === "active");

// Multi-item Basil: the BASE plan item's period governs, not an addon item's.
const addonItem = { price: { id: "price_overage_addon" }, current_period_start: nowUnix, current_period_end: futureUnix + 90 * 86400 };
await postWebhook(evt("evt_12", "customer.subscription.updated", basilSub("active", futureUnix + 30 * 86400, [addonItem])));
ok("multi-item Basil → period read from the mapped BASE item, not the addon", rowStatus3()?.current_period_end === isoOf(futureUnix + 30 * 86400));

// ── Founder-evidence row shape: a June trial row (status='trialing', no Stripe
//    binding, past trial_end, NULL period) receives a paid checkout's
//    subscription event. Before the fix the row ended exactly as observed in
//    prod: subscription_status='active' + status='trialing' + period NULL.
const UID4 = "usr_stripe4", WS4 = "ws_stripe4", CUS4 = "cus_4", SUB4 = "sub_4";
db.prepare(
  `INSERT INTO subscriptions (id, owner_user_id, workspace_id, plan, status, subscription_status, trial_start, trial_end, created_at, updated_at)
   VALUES ('sub_row_trial4', ?, ?, 'professional', 'trialing', 'trialing', '2026-06-23T00:00:00.000Z', '2026-07-07T00:00:00.000Z', datetime('now'), datetime('now'))`
).run(UID4, WS4);
const meta4 = { user_id: UID4, workspace_id: WS4, plan: "professional", interval: "monthly" };
await postWebhook(evt("evt_13", "customer.subscription.created", {
  id: SUB4, customer: CUS4, status: "active", metadata: meta4,
  items: { data: [{ price: { id: "price_pm" }, current_period_start: nowUnix, current_period_end: futureUnix }] },
}));
const repaired = db.prepare("SELECT id, subscription_status, status, current_period_end FROM subscriptions WHERE owner_user_id = ?").all(UID4);
ok("trial row upgraded in place (one row, no stacked pair)", repaired.length === 1 && repaired[0].id === "sub_row_trial4");
ok("trial row → subscription_status active", repaired[0]?.subscription_status === "active");
ok("trial row → legacy status re-synced to active (was 'trialing' in prod)", repaired[0]?.status === "active");
ok("trial row → current_period_end repaired from NULL", repaired[0]?.current_period_end === isoOf(futureUnix));

// ── P2-D trial-row branch: a LOCAL trial row with no owner binding is found by
//    workspace_id (not owner_user_id) and upgraded in place — the other UPDATE
//    path, which must hold the same lockstep + period guarantees.
const UID5 = "usr_stripe5", WS5 = "ws_stripe5", CUS5 = "cus_5", SUB5 = "sub_5";
db.prepare(
  `INSERT INTO subscriptions (id, owner_user_id, workspace_id, plan, status, subscription_status, trial_start, trial_end, created_at, updated_at)
   VALUES ('sub_row_trial5', NULL, ?, 'professional', 'trialing', 'trialing', '2026-06-23T00:00:00.000Z', '2026-07-07T00:00:00.000Z', datetime('now'), datetime('now'))`
).run(WS5);
await postWebhook(evt("evt_14", "customer.subscription.created", {
  id: SUB5, customer: CUS5, status: "active", metadata: { user_id: UID5, workspace_id: WS5, plan: "professional", interval: "monthly" },
  items: { data: [{ price: { id: "price_pm" }, current_period_start: nowUnix, current_period_end: futureUnix }] },
}));
const trialBranch = db.prepare("SELECT id, owner_user_id, subscription_status, status, current_period_end FROM subscriptions WHERE workspace_id = ?").all(WS5);
ok("trial-branch: one row, upgraded in place", trialBranch.length === 1 && trialBranch[0].id === "sub_row_trial5");
ok("trial-branch: owner bound and both status columns active", trialBranch[0]?.owner_user_id === UID5 && trialBranch[0]?.subscription_status === "active" && trialBranch[0]?.status === "active");
ok("trial-branch: current_period_end captured (Basil item)", trialBranch[0]?.current_period_end === isoOf(futureUnix));

// ── Global lockstep guard: NO row in the whole run diverges ──────────────────
ok("no subscriptions row has status != subscription_status after any webhook", divergentRows() === 0);

console.log(`\nStripe events: ${pass}/${pass + fail} passed`);
if (fail) { console.error("stripe-events validation FAILED"); process.exit(1); }
console.log("stripe-events validation passed");
