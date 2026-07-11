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
const rowStatus = () => db.prepare("SELECT subscription_status, plan FROM subscriptions WHERE owner_user_id = ? ORDER BY updated_at DESC LIMIT 1").get(UID);

// ── Invalid signature is rejected before any state change ────────────────────
const bad = await postWebhook(evt("evt_bad", "customer.subscription.created", subObj("active")), { secret: "whsec_WRONG" });
ok("invalid signature → 400", bad.status === 400);
ok("invalid signature wrote nothing", rowStatus() === undefined);

// ── customer.subscription.created → active + plan from the price ─────────────
const created = await postWebhook(evt("evt_1", "customer.subscription.created", subObj("active")));
ok("created accepted (2xx)", created.status >= 200 && created.status < 300);
ok("created → subscription_status active", rowStatus()?.subscription_status === "active");
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

// ── customer.subscription.updated (active) → restores active ─────────────────
await postWebhook(evt("evt_4", "customer.subscription.updated", subObj("active", "price_bm")));
ok("subsequent active update restores active", rowStatus()?.subscription_status === "active");

// ── customer.subscription.deleted → canceled (row retained) ─────────────────
const deleted = await postWebhook(evt("evt_5", "customer.subscription.deleted", { id: SUB, customer: CUS, status: "canceled", metadata: meta, current_period_end: futureUnix }));
ok("deleted accepted", deleted.status >= 200 && deleted.status < 300);
ok("deleted → subscription_status canceled", rowStatus()?.subscription_status === "canceled");
ok("deleted retains the row (historical record)", rowStatus() !== undefined);

console.log(`\nStripe events: ${pass}/${pass + fail} passed`);
if (fail) { console.error("stripe-events validation FAILED"); process.exit(1); }
console.log("stripe-events validation passed");
