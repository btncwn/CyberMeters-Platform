#!/usr/bin/env node
// Real Worker/router + SQLite; all provider calls intercepted before testing.
// Regression for pricing-page duplicate charging, missing workspace/consent,
// webhook storage failures acknowledged as success, and Starter CE access.
import assert from "node:assert/strict";
import { webcrypto } from "node:crypto";
import { loadWorker, buildDb, makeEnv, makeSeeder, makeCaller, ctx } from "./security/lib/worker-harness.js";
import { getEffectivePlanState } from "../workers/scan-api/src/engines/entitlements.js";

let passed = 0;
function check(name, actual, expected) { assert.deepEqual(actual, expected, name); passed++; }
const mod = await loadWorker();
const db = buildDb();
// The hand-made production table can enforce one subscription row per
// workspace (it predates the migrations that describe it). Mirror that rule so
// a webhook that moves a row onto an occupied workspace fails here too — the
// exact failure of the 11 Oct 2026 live payment.
db.exec("CREATE UNIQUE INDEX IF NOT EXISTS idx_test_subscriptions_workspace ON subscriptions (workspace_id) WHERE workspace_id IS NOT NULL");
const env = makeEnv(db);
const seed = await makeSeeder(db, mod);
for (const id of ["buyer", "foreign", "empty", "multiple", "viewer", "analyst", "admin"]) {
  seed.user(id, `${id}@billing.invalid`);
  await seed.session(`session-${id}`, id, `token-${id}`);
}
for (const [id, owner] of [["owned", "buyer"], ["other", "foreign"], ["multi-a", "multiple"], ["multi-b", "multiple"]]) {
  seed.workspace(id, owner, id);
  seed.member(`member-${id}`, id, owner, "owner");
}
for (const role of ["viewer", "analyst", "admin"]) {
  seed.member(`member-nonowner-${role}`, "owned", role, role);
}
seed.workspace("deleted", "buyer", "deleted", true);
const call = makeCaller(mod.default, env);
const requests = [];
const providerRequests = [];
// Stripe's own view of who is billed. The checkout consults it before creating
// a subscription, because our row cannot know when a webhook never landed.
const stripeCustomers = [];
let stripeLookupDown = false;
globalThis.fetch = async (url, opts = {}) => {
  providerRequests.push(url);
  if (url.startsWith("https://api.stripe.com/v1/customers?") || url.startsWith("https://api.stripe.com/v1/subscriptions?")) {
    if (stripeLookupDown) return Response.json({ error: { type: "api_error" } }, { status: 500 });
    const q = new URL(url).searchParams;
    if (url.includes("/v1/customers?")) {
      return Response.json({ data: stripeCustomers.filter(c => c.email === q.get("email")).map(c => ({ id: c.id, subscriptions: { data: c.subscriptions } })) });
    }
    return Response.json({ data: stripeCustomers.filter(c => c.id === q.get("customer")).flatMap(c => c.subscriptions) });
  }
  if (url === "https://api.stripe.com/v1/prices/price_sm") {
    return Response.json({ id: "price_sm", active: true, currency: "gbp", unit_amount: 999, recurring: { interval: "month" } });
  }
  if (["https://api.stripe.com/v1/checkout/sessions", "https://api.stripe.com/v1/billing_portal/sessions"].includes(url)) {
    const params = Object.fromEntries(new URLSearchParams(opts.body));
    requests.push({ url, params });
    const portal = url.includes("billing_portal");
    return Response.json({ id: `session-${requests.length}`, url: `https://${portal ? "billing" : "checkout"}.stripe.com/test-fixture` });
  }
  throw new Error(`Network forbidden: ${url}`);
};
const body = { plan: "starter", interval: "monthly", success_url: "https://app.cybermeters.com/checkout/success", cancel_url: "https://app.cybermeters.com/checkout/cancel" };
const checkout = (token, extra = {}) => call("POST", "/api/billing/checkout", token, { ...body, ...extra });
for (const [name, token, extra, status] of [
  ["anonymous", null, {}, 401], ["no owned workspace", "token-empty", {}, 409],
  ["ambiguous owned workspaces", "token-multiple", {}, 409],
  ["foreign workspace", "token-buyer", { workspace_id: "other" }, 403],
  ["deleted workspace", "token-buyer", { workspace_id: "deleted" }, 403],
  ["invalid explicit workspace", "token-buyer", { workspace_id: null }, 400],
  ["foreign redirect", "token-buyer", { success_url: "https://foreign.invalid/paid" }, 400],
]) {
  const count = requests.length;
  check(`${name} refused`, (await checkout(token, extra)).status, status);
  check(`${name} does not create a provider session`, requests.length, count);
}
// These are active workspace members with valid sessions, not merely foreign
// or logged-out callers. Even admin membership cannot authorize a charge.
for (const role of ["viewer", "analyst", "admin"]) {
  check(`${role} has working workspace read access`,
    (await call("GET", "/api/workspaces/owned/members", `token-${role}`)).status, 200);
  const before = providerRequests.length;
  check(`${role} cannot initiate explicit workspace billing`,
    (await checkout(`token-${role}`, { workspace_id: "owned" })).status, 403);
  check(`${role} denial makes no Stripe request`, providerRequests.length, before);
}
const fresh = await checkout("token-buyer");
check("unambiguous legacy caller can checkout", fresh.status, 200);
check("legacy checkout_url shape retained", fresh.data.checkout_url, "https://checkout.stripe.com/test-fixture");
let sent = requests.at(-1).params;
check("checkout session tied to authorized workspace", sent["metadata[workspace_id]"], "owned");
check("subscription tied to authorized workspace", sent["subscription_data[metadata][workspace_id]"], "owned");
check("owner identity authored by server", sent["metadata[user_id]"], "buyer");
check("terms acceptance required", sent["consent_collection[terms_of_service]"], "required");
check("immediate start consent supplied", Boolean(sent["custom_text[terms_of_service_acceptance][message]"]), true);
check("valid legacy success redirect retained", sent.success_url, body.success_url);
check("valid legacy cancel redirect retained", sent.cancel_url, body.cancel_url);
const freshMetadata = Object.fromEntries(["user_id", "workspace_id", "plan", "interval"].map(k => [k, sent[`metadata[${k}]`]]));
const explicit = await checkout("token-multiple", { workspace_id: "multi-b" });
check("explicit owned workspace resolves ambiguity", explicit.status, 200);
check("explicit selection is preserved", requests.at(-1).params["metadata[workspace_id]"], "multi-b");

let eventNumber = 0;
async function deliver(event, { badSignature = false } = {}) {
  const raw = JSON.stringify({ livemode: false, ...event });
  const timestamp = Math.floor(Date.now() / 1000);
  const key = await webcrypto.subtle.importKey("raw", new TextEncoder().encode(env.STRIPE_WEBHOOK_SECRET), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const signature = Buffer.from(await webcrypto.subtle.sign("HMAC", key, new TextEncoder().encode(`${timestamp}.${raw}`))).toString("hex");
  const res = await mod.default.fetch(new Request("https://api.cybermeters.com/api/billing/webhook", {
    method: "POST", headers: { "Stripe-Signature": `t=${timestamp},v1=${badSignature ? "bad" : signature}`, "CF-Connecting-IP": `192.0.2.${++eventNumber}` }, body: raw,
  }), env, ctx);
  return { status: res.status, data: await res.json() };
}
const completed = { id: "paid-completion", type: "checkout.session.completed", data: { object: { id: "cs-buyer", metadata: freshMetadata, customer: "cus-buyer", subscription: "sub-buyer", payment_status: "paid" } } };
check("bad signature refused", (await deliver(completed, { badSignature: true })).status, 400);
check("bad signature changes no subscription", db.prepare("SELECT COUNT(*) n FROM subscriptions WHERE owner_user_id='buyer'").get().n, 0);
check("matching completion accepted", (await deliver(completed)).status, 200);
check("matching completion activates purchased plan", (await getEffectivePlanState("buyer", env)).plan, "starter");
check("single workspace-bound subscription", db.prepare("SELECT workspace_id FROM subscriptions WHERE owner_user_id='buyer'").all().map(r => r.workspace_id), ["owned"]);
check("replay only after persisted completion", (await deliver(completed)).data.deduped, true);
check("replay does not add rows", db.prepare("SELECT COUNT(*) n FROM subscriptions WHERE owner_user_id='buyer'").get().n, 1);
const beforePaid = requests.length;
const paid = await checkout("token-buyer");
check("paid pricing-page caller opens portal", paid.data.portal, true);
check("paid legacy response usable by pricing page", paid.data.checkout_url, "https://billing.stripe.com/test-fixture");
check("no second subscription checkout", requests.slice(beforePaid).map(r => r.url), ["https://api.stripe.com/v1/billing_portal/sessions"]);
check("paid customer reused", requests.at(-1).params.customer, "cus-buyer");
const wsPaid = await call("POST", "/api/workspaces/owned/billing/checkout", "token-buyer", { plan: "starter" });
check("canonical workspace paid path remains portal", wsPaid.data.portal, true);
check("Starter CE is available", (await call("GET", "/api/workspaces/owned/cyber-essentials/answers", "token-buyer")).status, 200);
check("Starter CE remains tenant isolated", (await call("GET", "/api/workspaces/owned/cyber-essentials/answers", "token-foreign")).status, 403);
check("unentitled owner CE remains denied", (await call("GET", "/api/workspaces/other/cyber-essentials/answers", "token-foreign")).status, 403);

// A paid customer whose webhook never reached us has no Stripe ids on any row,
// so the row-based portal guard cannot see them. Stripe can: a second checkout
// must open their portal, never take another payment (11 Oct 2026 live case).
seed.user("returner", "returner@billing.invalid");
await seed.session("session-returner", "returner", "token-returner");
seed.workspace("ret-ws", "returner", "ret-ws");
seed.member("member-ret-ws", "ret-ws", "returner", "owner");
stripeCustomers.push({ id: "cus-ret", email: "returner@billing.invalid", subscriptions: [{ id: "sub-ret", status: "active" }] });
const beforeUnsynced = requests.length;
const unsynced = await checkout("token-returner");
check("billed-in-Stripe account is not charged again", unsynced.data.portal, true);
check("billed-in-Stripe reason is explicit", unsynced.data.reason, "existing_stripe_subscription");
check("billed-in-Stripe creates only a portal session", requests.slice(beforeUnsynced).map(r => r.url), ["https://api.stripe.com/v1/billing_portal/sessions"]);
check("portal opens for the billed Stripe customer", requests.at(-1).params.customer, "cus-ret");

stripeCustomers[stripeCustomers.length - 1].subscriptions = [{ id: "sub-ret", status: "incomplete" }];
check("an unpaid first attempt does not block paying with another card", (await checkout("token-returner")).data.checkout_url, "https://checkout.stripe.com/test-fixture");
check("retry checkout is a checkout session", requests.at(-1).url, "https://api.stripe.com/v1/checkout/sessions");

stripeLookupDown = true;
const beforeLookupDown = requests.length;
check("Stripe lookup failure refuses checkout", (await checkout("token-returner")).status, 503);
check("Stripe lookup failure creates no session", requests.length, beforeLookupDown);
stripeLookupDown = false;

// A stored customer whose local row is already cancelled but Stripe still bills.
seed.user("lapsed", "lapsed@billing.invalid");
await seed.session("session-lapsed", "lapsed", "token-lapsed");
seed.workspace("lapsed-ws", "lapsed", "lapsed-ws");
seed.member("member-lapsed-ws", "lapsed-ws", "lapsed", "owner");
db.prepare("INSERT INTO subscriptions (id, owner_user_id, workspace_id, plan, status, subscription_status, stripe_customer_id, updated_at) VALUES ('sub-row-lapsed','lapsed','lapsed-ws','starter','canceled','canceled','cus-lapsed', datetime('now'))").run();
stripeCustomers.push({ id: "cus-lapsed", email: "other@billing.invalid", subscriptions: [{ id: "sub-lapsed", status: "past_due" }] });
const lapsed = await checkout("token-lapsed");
check("stored customer Stripe still bills opens the portal", lapsed.data.portal, true);
check("stored customer portal uses the stored customer", requests.at(-1).params.customer, "cus-lapsed");

// Webhook row resolution: an owner with several historical rows. The Stripe
// customer already sits on one of them; the event must update THAT row. The
// old owner-first lookup took an arbitrary row, copied the customer onto it,
// hit the unique index and failed every retry — payment taken, plan never on.
seed.user("history", "history@billing.invalid");
seed.workspace("hist-old", "history", "hist-old");
seed.workspace("hist-new", "history", "hist-new");
db.prepare("INSERT INTO subscriptions (id, owner_user_id, workspace_id, plan, status, subscription_status, trial_start, trial_end, created_at, updated_at) VALUES ('sub-row-trial','history','hist-new','professional','trialing','trialing','2026-07-06 14:11:10','2026-07-20 14:11:10','2026-07-06 14:11:10','2026-07-06 14:11:10')").run();
db.prepare("INSERT INTO subscriptions (id, owner_user_id, workspace_id, plan, status, subscription_status, stripe_customer_id, created_at, updated_at) VALUES ('sub-row-hist','history','hist-old','business','canceled','canceled','cus-hist','2026-06-23 10:15:57','2026-10-08 20:30:39')").run();
const histMeta = { user_id: "history", workspace_id: "hist-new", plan: "starter", interval: "monthly" };
const histCompleted = await deliver({ id: "hist-completion", type: "checkout.session.completed", data: { object: { id: "cs-hist", metadata: histMeta, customer: "cus-hist", subscription: "sub-hist", payment_status: "paid" } } });
check("completion for a customer on a historical row is applied", histCompleted.status, 200);
check("the row that holds the customer is the one activated",
  { ...db.prepare("SELECT id, workspace_id, subscription_status, stripe_subscription_id FROM subscriptions WHERE stripe_customer_id='cus-hist'").get() },
  { id: "sub-row-hist", workspace_id: "hist-old", subscription_status: "active", stripe_subscription_id: "sub-hist" });
const histCreated = await deliver({ id: "hist-created", type: "customer.subscription.created", data: { object: { id: "sub-hist", customer: "cus-hist", status: "active", metadata: histMeta, items: { data: [{ price: { id: "price_sm", recurring: { interval: "month" } }, current_period_start: Math.floor(Date.now()/1000), current_period_end: Math.floor(Date.now()/1000) + 30 * 86400 }] } } } });
check("subscription.created for the same customer is applied", histCreated.status, 200);
check("historical owner now holds the purchased plan", (await getEffectivePlanState("history", env)).plan, "starter");
check("no extra subscription row was invented", db.prepare("SELECT COUNT(*) n FROM subscriptions WHERE owner_user_id='history'").get().n, 2);

// The 11 Oct 2026 live case exactly: no Stripe ids anywhere, a lapsed trial in
// the paying workspace and a cancelled row in another. The old lookup took the
// other workspace's row and moved it onto the paying workspace — a unique
// workspace_id violation on every retry. The paying workspace's row is the one.
seed.user("mirror", "mirror@billing.invalid");
seed.workspace("mirror-old", "mirror", "mirror-old");
seed.workspace("mirror-ws", "mirror", "mirror-ws");
db.prepare("INSERT INTO subscriptions (id, owner_user_id, workspace_id, plan, status, subscription_status, created_at, updated_at) VALUES ('sub-row-mirror-old','mirror','mirror-old','business','canceled','canceled','2026-06-23 10:15:57','2026-10-08 20:30:39')").run();
db.prepare("INSERT INTO subscriptions (id, owner_user_id, workspace_id, plan, status, subscription_status, trial_start, trial_end, created_at, updated_at) VALUES ('sub-row-mirror-trial','mirror','mirror-ws','professional','trialing','trialing','2026-07-06 14:11:10','2026-07-20 14:11:10','2026-07-06 14:11:10','2026-07-06 14:11:10')").run();
const mirrorMeta = { workspace_id: "mirror-ws", interval: "monthly", user_id: "mirror", plan: "starter" };
check("live-case completion is applied", (await deliver({ id: "mirror-completion", type: "checkout.session.completed", data: { object: { id: "cs-mirror", metadata: mirrorMeta, customer: "cus-mirror", subscription: "sub-mirror", payment_status: "paid", status: "complete" } } })).status, 200);
check("live-case subscription.created is applied", (await deliver({ id: "mirror-created", type: "customer.subscription.created", data: { object: { id: "sub-mirror", customer: "cus-mirror", status: "active", metadata: mirrorMeta, items: { data: [{ price: { id: "price_sm", recurring: { interval: "month" } }, current_period_start: Math.floor(Date.now()/1000), current_period_end: Math.floor(Date.now()/1000) + 30 * 86400 }] } } } })).status, 200);
check("the paying workspace's row carries the subscription",
  { ...db.prepare("SELECT id, subscription_status, stripe_subscription_id FROM subscriptions WHERE workspace_id='mirror-ws'").get() },
  { id: "sub-row-mirror-trial", subscription_status: "active", stripe_subscription_id: "sub-mirror" });
check("the other workspace's history is untouched",
  { ...db.prepare("SELECT workspace_id, subscription_status, stripe_customer_id FROM subscriptions WHERE id='sub-row-mirror-old'").get() },
  { workspace_id: "mirror-old", subscription_status: "canceled", stripe_customer_id: null });
check("live-case owner holds the purchased plan", (await getEffectivePlanState("mirror", env)).plan, "starter");

// Targeted storage errors wrap only the named D1 statement. SQLite handles
// every other query normally; the test never fakes a completed marker.
const realD1 = env.cybermeters_db;
function faultMatching(pattern, method, { noChange = false } = {}) {
  env.cybermeters_db = { ...realD1, prepare(sql) {
    const wrap = (stmt) => new Proxy(stmt, { get(target, key) {
      if (key === "bind") return (...args) => wrap(target.bind(...args));
      if (key === method && pattern.test(sql)) return async () => {
        if (noChange) return { meta: { changes: 0 } };
        throw new Error("controlled billing storage failure");
      };
      return Reflect.get(target, key);
    } });
    return wrap(realD1.prepare(sql));
  } };
}
const subscriptionReads = /SELECT id, owner_user_id, workspace_id, plan, status/;
faultMatching(subscriptionReads, "all");
const beforeReadFault = requests.length;
check("paid-state read fault refuses checkout", (await checkout("token-buyer")).status, 500);
check("paid-state read fault never creates second checkout", requests.length, beforeReadFault);
env.cybermeters_db = realD1;
function event(id) { return { id, type: "customer.subscription.updated", data: { object: { id: "sub-buyer", customer: "cus-buyer", metadata: freshMetadata, status: "active", items: { data: [{ price: { id: "price_sm" } }] }, current_period_end: Math.floor(Date.now()/1000) + 86400 } } }; }
const insertClaim = /INSERT OR IGNORE INTO stripe_processed_events/;
const readClaim = /SELECT status, processed_at FROM stripe_processed_events/;
const reclaim = /UPDATE stripe_processed_events SET status = 'processing'/;
const finishClaim = /UPDATE stripe_processed_events SET status = 'completed'/;
for (const [id, pattern, method, seedStatus, opts] of [
  ["insert-fault", insertClaim, "run", null, {}],
  ["read-fault", readClaim, "first", "failed", {}],
  ["reclaim-fault", reclaim, "run", "failed", {}],
  ["reclaim-lost", reclaim, "run", "failed", { noChange: true }],
  ["missing-claim", insertClaim, "run", null, { noChange: true }],
  ["finish-fault", finishClaim, "run", null, {}],
  ["finish-missing", finishClaim, "run", null, { noChange: true }],
]) {
  if (seedStatus) db.prepare("INSERT INTO stripe_processed_events(id,event_type,status,processed_at) VALUES(?, 'test', ?, '2000-01-01 00:00:00')").run(id, seedStatus);
  const input = event(id);
  faultMatching(pattern, method, opts);
  const failed = await deliver(input);
  check(`${id} returns retryable 503`, failed.status, 503);
  check(`${id} does not claim deduplication`, Boolean(failed.data.deduped), false);
  env.cybermeters_db = realD1;
  check(`${id} retries successfully after recovery`, (await deliver(input)).status, 200);
  check(`${id} records successful completion`, db.prepare("SELECT status FROM stripe_processed_events WHERE id=?").get(id).status, "completed");
  check(`${id} completed replay deduped`, (await deliver(input)).data.deduped, true);
}
db.prepare("INSERT INTO stripe_processed_events(id,event_type,status,processed_at) VALUES('inflight','test','processing',datetime('now'))").run();
const beforeInflight = db.prepare("SELECT COUNT(*) n FROM subscription_events").get().n;
check("concurrent inflight is retryable, not completed", (await deliver(event("inflight"))).status, 503);
check("concurrent inflight creates no billing effects", db.prepare("SELECT COUNT(*) n FROM subscription_events").get().n, beforeInflight);
db.prepare("UPDATE stripe_processed_events SET processed_at='2000-01-01 00:00:00' WHERE id='inflight'").run();
check("crashed stale claim recovers", (await deliver(event("inflight"))).status, 200);
check("missing event identity refused", (await deliver({ type: "test", data: { object: {} } })).status, 400);
console.log(`First-customer billing: ${passed}/${passed} passed (real router + SQLite, no external calls)`);
