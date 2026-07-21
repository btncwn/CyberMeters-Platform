#!/usr/bin/env node
//
// M7 B2/B3 go-live billing-flow validator (founder-approved 21 Jul 2026).
//
// B2 — checkout consent: every Stripe Checkout Session must require Terms
//      acceptance (consent_collection.terms_of_service='required') and state
//      the immediate-start / 14-day cooling-off waiver next to it, using ONLY
//      the approved policy wording (no refunds of prepaid fees except where
//      required by law; the free 14-day trial exists to try first). Consent is
//      recorded from the completed session in the webhook audit trail.
// B3 — portal-only plan changes: a customer with an ACTIVE PAID Stripe-bound
//      subscription must be routed to the billing portal, never into a fresh
//      subscription-mode checkout (which always creates a SECOND subscription;
//      nothing cancels the old one, so both would bill). Trial / free / manual
//      rows keep the fresh-checkout path.
//
// Pure/behavioural harness over the REAL production helpers + source-wiring
// anchors + load-bearing mutations. No live D1/R2/network. Node 24+. CI-blocking.

import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const STRIPE_SRC = path.join(ROOT, "workers", "scan-api", "src", "engines", "stripe.js");
const BILLING_ROUTE_SRC = path.join(ROOT, "workers", "scan-api", "src", "routes", "billing.js");
const GLOBAL_BILLING_SRC = path.join(ROOT, "workers", "scan-api", "src", "routes", "global-billing.js");

const {
  applyCheckoutConsentParams,
  CHECKOUT_IMMEDIATE_START_CONSENT_TEXT,
  shouldRoutePlanChangeToPortal,
} = await import(pathToFileURL(STRIPE_SRC).href);

let pass = 0, fail = 0;
const ok = (name, cond, detail = "") => {
  cond ? pass++ : fail++;
  console.log(`${cond ? "ok  " : "FAIL"} - ${name}${!cond && detail ? ` -- ${detail}` : ""}`);
};

const future = new Date(Date.now() + 30 * 24 * 3600 * 1000).toISOString();
const past   = new Date(Date.now() - 30 * 24 * 3600 * 1000).toISOString();

// ── SECTION A — B2 consent params ────────────────────────────────────────────
const params = applyCheckoutConsentParams(new URLSearchParams());
ok("A1 consent_collection[terms_of_service] = required",
  params.get("consent_collection[terms_of_service]") === "required");
const msg = params.get("custom_text[terms_of_service_acceptance][message]") || "";
ok("A2 waiver message is attached to the Terms checkbox", msg.length > 0 && msg === CHECKOUT_IMMEDIATE_START_CONSENT_TEXT);
ok("A3 message names the Terms of Service", /Terms of Service/.test(msg));
ok("A4 message states the service starts immediately", /starts immediately|begins straight away/.test(msg));
ok("A5 message states the 14-day cooling-off right is given up", /14-day consumer cancellation \(cooling-off\) right/.test(msg));
ok("A6 message states non-refundable EXCEPT where required by law", /non-refundable except where required by law/.test(msg));
ok("A7 message points at the free 14-day trial", /free 14-day trial/.test(msg));
ok("A8 message offers NO rights beyond policy (no money-back / guarantee wording)",
  !/money[\s-]?back|guarantee|full refund/i.test(msg));
ok("A9 helper returns the same params object (chainable into session creation)",
  applyCheckoutConsentParams(params) === params);

// ── SECTION B — B3 portal-routing predicate ──────────────────────────────────
const paidActive = {
  id: "row1", stripe_customer_id: "cus_x", stripe_subscription_id: "sub_x",
  subscription_status: "active", current_period_end: future,
};
ok("B1 active paid Stripe sub → portal", shouldRoutePlanChangeToPortal(paidActive) === true);
ok("B2 local trial row (no Stripe ids) → fresh checkout",
  shouldRoutePlanChangeToPortal({ id: "row2", subscription_status: "trialing", trial_end: future }) === false);
ok("B3 no subscription row → fresh checkout", shouldRoutePlanChangeToPortal(null) === false);
ok("B4 canceled sub (ids present) → fresh checkout",
  shouldRoutePlanChangeToPortal({ ...paidActive, subscription_status: "canceled" }) === false);
ok("B5 active status but period ended → fresh checkout",
  shouldRoutePlanChangeToPortal({ ...paidActive, current_period_end: past }) === false);
ok("B6 past_due INSIDE payment grace → portal (fix payment / switch there, never stack)",
  shouldRoutePlanChangeToPortal({ ...paidActive, subscription_status: "past_due", payment_failed_at: new Date().toISOString() }) === true);
ok("B7 past_due with grace expired → fresh checkout",
  shouldRoutePlanChangeToPortal({ ...paidActive, subscription_status: "past_due", payment_failed_at: past }) === false);
ok("B8 active manual row without a Stripe customer → fresh checkout (portal impossible)",
  shouldRoutePlanChangeToPortal({ ...paidActive, stripe_customer_id: null }) === false);
ok("B9 active row with customer but NO Stripe subscription → fresh checkout",
  shouldRoutePlanChangeToPortal({ ...paidActive, stripe_subscription_id: null }) === false);

// ── SECTION C — source wiring anchors ────────────────────────────────────────
const billingSrc = fs.readFileSync(BILLING_ROUTE_SRC, "utf8");
const globalSrc  = fs.readFileSync(GLOBAL_BILLING_SRC, "utf8");
ok("C1 checkout route applies the consent params", billingSrc.includes("applyCheckoutConsentParams(params);"));
ok("C2 checkout route guards with shouldRoutePlanChangeToPortal", billingSrc.includes("if (shouldRoutePlanChangeToPortal(currentSub)) {"));
ok("C3 guard resolves the CANONICAL subscription (not a raw newest-row read)",
  billingSrc.includes("const currentSub = await getWorkspaceSubscription(wsId, env);"));
ok("C4 portal redirect is audited", billingSrc.includes('"billing_checkout_routed_to_portal"'));
ok("C5 guard sits BEFORE checkout-session creation",
  billingSrc.indexOf("if (shouldRoutePlanChangeToPortal(currentSub)) {") <
  billingSrc.indexOf('fetch("https://api.stripe.com/v1/checkout/sessions"'));
ok("C6 completed-checkout webhook records the Stripe-collected consent",
  (globalSrc.match(/terms_consent: obj\?\.consent\?\.terms_of_service \?\? null,/g) || []).length >= 2);

// ── Mutation harness — every guard must be load-bearing ──────────────────────
async function mutant(srcPath, from, to) {
  const src = fs.readFileSync(srcPath, "utf8");
  if (!src.includes(from)) return { anchor: false };
  const srcUrl = pathToFileURL(srcPath);
  const rewritten = src.replace(from, to)
    .replace(/from "(\.\.?\/[^"]+)"/g, (_m, rel) => `from ${JSON.stringify(new URL(rel, srcUrl).href)}`);
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "ccp-"));
  const file = path.join(dir, "m.mjs");
  fs.writeFileSync(file, rewritten);
  let mod = null;
  try { mod = await import(`${pathToFileURL(file).href}?t=${Date.now()}-${Math.random()}`); }
  finally { fs.rmSync(dir, { recursive: true, force: true }); }
  return { anchor: true, mod };
}

// M1: Stripe-subscription-id requirement dropped → a manual/customer-only row
// falsely routes to portal (B9 would fail).
{
  const m = await mutant(STRIPE_SRC,
    "  if (!sub.stripe_customer_id || !sub.stripe_subscription_id) return false;",
    "  if (!sub.stripe_customer_id) return false;");
  ok("mutation M1 (sub-id requirement dropped) → customer-only row falsely portal — CAUGHT",
    m.anchor && m.mod.shouldRoutePlanChangeToPortal({ ...paidActive, stripe_subscription_id: null }) === true);
}
// M2: liveness check replaced with always-true → canceled/expired rows falsely
// route to portal and can never reach checkout again (B4/B5 would fail).
{
  const m = await mutant(STRIPE_SRC,
    "  return isSubscriptionActive(sub) || getPaymentGraceState(sub).active;",
    "  return true;");
  ok("mutation M2 (liveness check removed) → canceled sub falsely portal — CAUGHT",
    m.anchor && m.mod.shouldRoutePlanChangeToPortal({ ...paidActive, subscription_status: "canceled" }) === true);
}
// M3: consent_collection line dropped → checkout would render NO required Terms
// checkbox (A1 would fail).
{
  const m = await mutant(STRIPE_SRC,
    '  params.set("consent_collection[terms_of_service]", "required");',
    "");
  const p = m.anchor ? m.mod.applyCheckoutConsentParams(new URLSearchParams()) : null;
  ok("mutation M3 (consent_collection dropped) → no required Terms checkbox — CAUGHT",
    m.anchor && p.get("consent_collection[terms_of_service]") === null);
}
// M4: waiver text neutered → the immediate-start waiver is no longer stated
// (A5/A6 would fail).
{
  const m = await mutant(STRIPE_SRC,
    "give up the 14-day consumer cancellation (cooling-off) right",
    "may cancel at any time");
  const p = m.anchor ? m.mod.applyCheckoutConsentParams(new URLSearchParams()) : null;
  ok("mutation M4 (waiver wording removed) → cooling-off waiver no longer stated — CAUGHT",
    m.anchor && !/14-day consumer cancellation \(cooling-off\) right/.test(p.get("custom_text[terms_of_service_acceptance][message]") || ""));
}

console.log(`\ncheckout-consent-portal: ${pass}/${pass + fail} passed`);
if (fail) { console.error("checkout-consent-portal validation FAILED"); process.exit(1); }
console.log("checkout-consent-portal validation passed");
