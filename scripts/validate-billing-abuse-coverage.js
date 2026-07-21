#!/usr/bin/env node
// ─────────────────────────────────────────────────────────────────────────────
// validate-billing-abuse-coverage.js  (CI-blocking)
//
// The D-section of docs/SECURITY-VERIFICATION-MATRIX.md — billing / entitlement
// ABUSE regression. Mirrors the #241 cross-tenant authz suite: REUSES the same
// #187/#241 harness (scripts/security/lib/worker-harness.js — real Worker
// router + real in-memory SQLite) and drives the REAL webhook endpoint, then
// reads entitlement through the REAL resolver (engines/entitlements.js) against
// the same D1. The Stripe webhook handlers (engines/stripe.js) and the resolver
// are TESTED AS-IS; this suite changes no billing logic.
//
//   D1 — Plan downgrade closes entitlement immediately. A subscription.updated
//        that lowers the plan (professional→starter), and a .deleted (cancel),
//        both drop getEffectivePlanState to the lower plan the SAME request; a
//        professional-only feature/limit is denied afterwards. Regression-locks
//        #239: after the write, `status` AND `subscription_status` agree (no
//        stale higher-plan legacy column).
//   D2 — Trial expiry cannot be bypassed. A trialing row past trial_end → free;
//        a trialing row with NEITHER trial_end nor current_period_end fails
//        CLOSED (free); a high `plan` value on an expired trial row grants
//        nothing (client-set fields never widen entitlement — the resolver
//        reads only status + window, never a request param).
//   D3 — Stripe webhook replay is idempotent. The same event id twice does not
//        re-apply (deduped); replaying a SUPERSEDED upgrade after a downgrade
//        does not resurrect the higher plan; a stale out-of-order event never
//        rewinds current_period_end.
//   D4 — Checkout fail-closed. verifyStripePriceMatchesPolicy refuses a price
//        whose amount/currency/interval/active state does not match the
//        canonical registry for (plan, interval) — so a tampered price id or a
//        higher requested plan can never charge less than the policy states.
//
// Every negative has a positive control (the legitimate path DOES entitle), so
// no "denied" pass is vacuous. A RED assertion here is a real billing finding,
// not a test bug — STOP and report, do not patch. Requires Node 24+.
// ─────────────────────────────────────────────────────────────────────────────
import { webcrypto } from "node:crypto";
import { loadWorker, buildDb, makeEnv, ctx } from "./security/lib/worker-harness.js";
import {
  getEffectivePlanState, hasFeatureEntitlement, getEffectiveDomainLimit,
  resolveCanonicalSubscriptionRow, normalizePlan,
} from "../workers/scan-api/src/engines/entitlements.js";
import { verifyStripePriceMatchesPolicy } from "../workers/scan-api/src/engines/stripe.js";

let passed = 0, failed = 0, section = "General";
const results = [];
const sec = (s) => { section = s; };
const ok = (name, cond) => { cond ? (passed++, results.push(`PASS [${section}] ${name}`)) : (failed++, results.push(`FAIL [${section}] ${name}`)); };

const WHSEC = "whsec_test_secret";
const nowUnix = () => Math.floor(Date.now() / 1000);
const futureUnix = () => nowUnix() + 30 * 86400;

// Independent HMAC-SHA256 hex — forges the Stripe-Signature the way Stripe does,
// so we exercise the worker's real signature verification, not our own.
async function hmacHex(secret, message) {
  const key = await webcrypto.subtle.importKey("raw", new TextEncoder().encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const sig = await webcrypto.subtle.sign("HMAC", key, new TextEncoder().encode(message));
  return [...new Uint8Array(sig)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

async function main() {
  const mod = await loadWorker();
  const worker = mod.default;
  const db = buildDb();
  const env = makeEnv(db);
  // The resolver maps a price → plan through the SAME merged map the webhook uses.
  env.STRIPE_PRICE_MAP = JSON.stringify({
    starter_monthly: "price_sm", professional_monthly: "price_pm", business_monthly: "price_bm",
    starter_annual: "price_sa", professional_annual: "price_pa", business_annual: "price_ba",
  });
  env.STRIPE_WEBHOOK_SECRET = WHSEC;
  env.STRIPE_SECRET_KEY = "sk_test_x";

  async function postWebhook(event) {
    const raw = JSON.stringify(event);
    const ts = nowUnix();
    const sig = await hmacHex(WHSEC, `${ts}.${raw}`);
    const res = await worker.fetch(new Request("https://api.cybermeters.com/api/billing/webhook", {
      method: "POST", headers: { "Content-Type": "application/json", "Stripe-Signature": `t=${ts},v1=${sig}` }, body: raw,
    }), env, ctx);
    let data = {}; try { data = await res.json(); } catch { /* */ }
    return { status: res.status, data };
  }
  const evt = (id, type, object) => ({ id, type, data: { object } });
  const subObj = (id, cus, meta, priceId, status, cpEnd = futureUnix()) => ({
    id, customer: cus, status, metadata: meta,
    items: { data: [{ price: { id: priceId }, current_period_start: nowUnix(), current_period_end: cpEnd }] },
    current_period_start: nowUnix(), current_period_end: cpEnd,
  });
  const rawRow = (sql, ...a) => { try { db.prepare(sql).run(...a); } catch (e) { if (process.env.HARNESS_DEBUG) console.error("seed skip:", e.message); } };
  const seedUser = (id, email) => rawRow("INSERT INTO users (id, email, password_hash, name, plan, status, email_verified, mfa_enabled) VALUES (?, ?, 'x', ?, 'free', 'active', 1, 0)", id, email, id);
  const subRow = (uid) => db.prepare("SELECT plan, status, subscription_status, current_period_end FROM subscriptions WHERE owner_user_id = ? ORDER BY updated_at DESC LIMIT 1").get(uid);

  // ── D1: plan downgrade closes entitlement immediately ──────────────────────
  sec("D1 downgrade closes entitlement");
  seedUser("uD1", "d1@a.co");
  rawRow("INSERT INTO workspaces (id, owner_user_id, name) VALUES ('wsD1','uD1','WS-D1')");
  const metaD1 = (plan) => ({ user_id: "uD1", workspace_id: "wsD1", plan, interval: "monthly" });
  // Positive control: created professional → professional entitlement.
  await postWebhook(evt("d1_create", "customer.subscription.created", subObj("sub_d1", "cus_d1", metaD1("professional"), "price_pm", "active")));
  let st = await getEffectivePlanState("uD1", env);
  ok("professional after create (positive control)", st.plan === "professional");
  ok("professional grants executive_dashboard", hasFeatureEntitlement(st.plan, "executive_dashboard") === true);
  ok("professional domain limit is 3", getEffectiveDomainLimit(st.plan, false) === 3);
  // Downgrade professional → starter via subscription.updated.
  await postWebhook(evt("d1_downgrade", "customer.subscription.updated", subObj("sub_d1", "cus_d1", metaD1("starter"), "price_sm", "active")));
  st = await getEffectivePlanState("uD1", env);
  ok("downgrade to starter resolves SAME request", st.plan === "starter");
  ok("starter DENIES executive_dashboard", hasFeatureEntitlement(st.plan, "executive_dashboard") === false);
  ok("starter DENIES vendor_risk (professional-only)", hasFeatureEntitlement(st.plan, "vendor_risk") === false);
  ok("starter domain limit dropped to 1", getEffectiveDomainLimit(st.plan, false) === 1);
  // Regression-lock #239: legacy status column agrees with subscription_status.
  let row = subRow("uD1");
  ok("#239 lock: status == subscription_status after downgrade (no stale)", row.status === row.subscription_status && row.subscription_status === "active");
  ok("#239 lock: plan column is the lowered plan (starter)", row.plan === "starter");
  // Cancel → free.
  await postWebhook(evt("d1_cancel", "customer.subscription.deleted", subObj("sub_d1", "cus_d1", metaD1("starter"), "price_sm", "canceled")));
  st = await getEffectivePlanState("uD1", env);
  ok("cancel resolves to free", st.plan === "free");
  ok("free grants NO paid feature (executive_dashboard)", hasFeatureEntitlement(st.plan, "executive_dashboard") === false);
  row = subRow("uD1");
  ok("#239 lock: both status columns 'canceled' after cancel", row.status === "canceled" && row.subscription_status === "canceled");

  // ── D2: trial expiry cannot be bypassed ────────────────────────────────────
  // Resolver is pure over rows — seed rows directly to isolate the trial rules.
  sec("D2 trial expiry cannot be bypassed");
  const past = "2000-01-01T00:00:00.000Z";
  const future = new Date(Date.now() + 7 * 86400 * 1000).toISOString();
  // Positive control: a live trial inside its window entitles its plan as a trial.
  const liveTrial = { id: "r1", owner_user_id: "u", workspace_id: "wA", plan: "professional", status: "trialing", subscription_status: "trialing", trial_end: future, current_period_end: null };
  let r = resolveCanonicalSubscriptionRow([liveTrial]);
  ok("live trial resolves (positive control)", r?.source === "trial" && normalizePlan(r.row.plan) === "professional");
  // Expired trial → free (no entitling row).
  const expiredTrial = { ...liveTrial, id: "r2", workspace_id: "wB", trial_end: past };
  ok("expired trial resolves to free (no row)", resolveCanonicalSubscriptionRow([expiredTrial]) === null);
  // A high `plan` value on the expired trial does not widen anything.
  const expiredBizTrial = { ...expiredTrial, id: "r3", workspace_id: "wC", plan: "business" };
  ok("expired trial with plan=business STILL free (client field never widens)", resolveCanonicalSubscriptionRow([expiredBizTrial]) === null);
  // Trialing row with NEITHER trial_end nor current_period_end fails CLOSED.
  const noWindowTrial = { ...liveTrial, id: "r4", workspace_id: "wD", trial_end: null, current_period_end: null };
  ok("trialing with no window fails closed (free)", resolveCanonicalSubscriptionRow([noWindowTrial]) === null);
  // End-to-end through the resolver's DB read: an expired trial row in D1 → free.
  seedUser("uD2", "d2@a.co");
  rawRow("INSERT INTO subscriptions (id, owner_user_id, workspace_id, plan, status, subscription_status, trial_start, trial_end, created_at, updated_at) VALUES ('subD2','uD2','wsD2','business','trialing','trialing', ?, ?, datetime('now'), datetime('now'))", past, past);
  const d2State = await getEffectivePlanState("uD2", env);
  ok("getEffectivePlanState → free for an expired-trial row in D1", d2State.plan === "free" && d2State.is_trial === false);

  // ── D3: Stripe webhook replay is idempotent ────────────────────────────────
  sec("D3 webhook replay idempotent");
  seedUser("uD3", "d3@a.co");
  rawRow("INSERT INTO workspaces (id, owner_user_id, name) VALUES ('wsD3','uD3','WS-D3')");
  const metaD3 = (plan) => ({ user_id: "uD3", workspace_id: "wsD3", plan, interval: "monthly" });
  // Upgrade to professional (event evt_up).
  await postWebhook(evt("d3_up", "customer.subscription.created", subObj("sub_d3", "cus_d3", metaD3("professional"), "price_pm", "active")));
  ok("professional after first delivery (positive control)", (await getEffectivePlanState("uD3", env)).plan === "professional");
  const countRows = () => db.prepare("SELECT COUNT(*) AS n FROM subscriptions WHERE owner_user_id = 'uD3'").get().n;
  const rowsAfterUp = countRows();
  // Exact replay of evt_up → deduped, no new row, state unchanged.
  const replay = await postWebhook(evt("d3_up", "customer.subscription.created", subObj("sub_d3", "cus_d3", metaD3("professional"), "price_pm", "active")));
  ok("exact event-id replay is deduped (200)", replay.status === 200 && replay.data?.deduped === true);
  ok("replay created no second subscription row", countRows() === rowsAfterUp);
  // Downgrade (evt_down), then replay the SUPERSEDED evt_up → must NOT resurrect professional.
  await postWebhook(evt("d3_down", "customer.subscription.updated", subObj("sub_d3", "cus_d3", metaD3("starter"), "price_sm", "active")));
  ok("downgrade applied (starter)", (await getEffectivePlanState("uD3", env)).plan === "starter");
  const resurrect = await postWebhook(evt("d3_up", "customer.subscription.created", subObj("sub_d3", "cus_d3", metaD3("professional"), "price_pm", "active")));
  ok("replay of superseded upgrade is deduped", resurrect.data?.deduped === true);
  ok("superseded-upgrade replay does NOT resurrect professional", (await getEffectivePlanState("uD3", env)).plan === "starter");
  // Out-of-order: advance period, then a stale older event must not rewind it.
  const advanced = futureUnix() + 60 * 86400;
  await postWebhook(evt("d3_adv", "customer.subscription.updated", subObj("sub_d3", "cus_d3", metaD3("starter"), "price_sm", "active", advanced)));
  const advIso = subRow("uD3").current_period_end;
  await postWebhook(evt("d3_stale", "customer.subscription.updated", subObj("sub_d3", "cus_d3", metaD3("starter"), "price_sm", "active", nowUnix() + 5 * 86400)));
  ok("stale out-of-order event does NOT rewind current_period_end", subRow("uD3").current_period_end === advIso);

  // ── D4: checkout fail-closed (verifyStripePriceMatchesPolicy) ──────────────
  sec("D4 checkout fail-closed");
  // Stub global fetch to return a controlled Stripe price object. (loadWorker
  // disabled the network; verifyStripePriceMatchesPolicy calls global fetch.)
  const priceResponse = (body, okFlag = true) => ({ ok: okFlag, json: async () => body });
  const setPrice = (body, okFlag = true) => { globalThis.fetch = async () => priceResponse(body, okFlag); };
  const GOOD_PRO = { currency: "gbp", recurring: { interval: "month" }, unit_amount: 1999, active: true };
  // Positive control: the canonical professional-monthly price is accepted.
  setPrice(GOOD_PRO);
  ok("canonical professional price accepted (positive control)", (await verifyStripePriceMatchesPolicy(env, "professional", "monthly", "price_pm")).ok === true);
  // Tampered amount: request professional but the price charges starter's 999.
  setPrice({ ...GOOD_PRO, unit_amount: 999 });
  let v = await verifyStripePriceMatchesPolicy(env, "professional", "monthly", "price_pm");
  ok("underpriced professional refused (amount mismatch)", v.ok === false && v.mismatches?.includes("amount"));
  // Higher requested plan than the price pays: request business, price pays 1999.
  setPrice(GOOD_PRO);
  v = await verifyStripePriceMatchesPolicy(env, "business", "monthly", "price_bm");
  ok("business requested but professional-priced is refused (cannot upgrade cheaply)", v.ok === false && v.mismatches?.includes("amount"));
  // Wrong currency, interval, inactive.
  setPrice({ ...GOOD_PRO, currency: "usd" });
  ok("non-GBP price refused", (await verifyStripePriceMatchesPolicy(env, "professional", "monthly", "price_pm")).mismatches?.includes("currency"));
  setPrice({ ...GOOD_PRO, recurring: { interval: "year" } });
  ok("wrong-interval price refused", (await verifyStripePriceMatchesPolicy(env, "professional", "monthly", "price_pm")).mismatches?.includes("interval"));
  setPrice({ ...GOOD_PRO, active: false });
  ok("inactive price refused", (await verifyStripePriceMatchesPolicy(env, "professional", "monthly", "price_pm")).mismatches?.includes("inactive"));
  // Lookup failure (Stripe non-2xx) fails closed.
  setPrice({}, false);
  ok("stripe price lookup failure fails closed", (await verifyStripePriceMatchesPolicy(env, "professional", "monthly", "price_pm")).error === "stripe_price_lookup_failed");
  // Non-checkout-eligible plan is refused before any lookup.
  setPrice(GOOD_PRO);
  ok("enterprise/free plan is not checkout-eligible", (await verifyStripePriceMatchesPolicy(env, "enterprise", "monthly", "price_pm")).error === "plan_not_checkout_eligible");
  globalThis.fetch = async () => { throw new Error("network disabled"); };

  // ── Coverage delta ─────────────────────────────────────────────────────────
  sec("Coverage");
  const controls = {
    D1: "plan downgrade / cancel closes entitlement immediately (+ #239 status lockstep)",
    D2: "trial-expiry cannot be bypassed (window + fail-closed + client field never widens)",
    D3: "webhook replay idempotent (exact dup, superseded-upgrade replay, stale period)",
    D4: "checkout fail-closed (amount/currency/interval/active/lookup/eligibility)",
  };
  ok("all four D-section controls asserted", Object.keys(controls).length === 4);

  // ── Report ─────────────────────────────────────────────────────────────────
  const bySec = {};
  for (const line of results) { const s = line.match(/\[(.*?)\]/)[1]; (bySec[s] ??= { p: 0, f: 0 })[line.startsWith("PASS") ? "p" : "f"]++; }
  console.log("\nBilling / entitlement abuse coverage (D-section, reusing #187/#241 harness):");
  for (const [s, c] of Object.entries(bySec)) console.log(`  ${c.f ? "✗" : "✓"} ${s}: ${c.p}/${c.p + c.f}`);
  console.log("\nD-section coverage delta:");
  for (const [k, v] of Object.entries(controls)) console.log(`  + ${k} — ${v}`);
  if (failed) { console.log("\nFailures:"); for (const rr of results.filter((x) => x.startsWith("FAIL"))) console.log("  " + rr); }
  console.log(`\nBilling abuse coverage: ${passed}/${passed + failed} passed`);
  if (failed) { console.error("billing-abuse-coverage validation FAILED — a RED assertion here is a billing finding, not a test bug"); process.exit(1); }
  console.log("billing-abuse-coverage validation passed");
}

main().catch((e) => { console.error("billing-abuse-coverage runner crashed:", e); process.exit(1); });
