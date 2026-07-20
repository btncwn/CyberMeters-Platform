#!/usr/bin/env node
//
// Pricing-policy lockstep parity: the canonical pricing registry (and every
// runtime table derived from it) must state EXACTLY the founder-locked ladder
// in docs/PRICING-POLICY.md (LOCKED 2026-07-19) — Trial £0/14d/1 domain,
// Starter £9.99/1, Professional £19.99/3, Business £49.99/10 (+£3 to 25),
// MSP £99.99 base + £3/domain min 10 (floor £129.99), annual = exactly 10 ×
// monthly. Also pins the fail-closed billing guards: unknown Stripe price maps
// to NO plan (never the metadata fallback), the merged price map honours the
// individual env vars checkout already uses, checkout refuses a Stripe price
// that does not charge the policy amount, the trial caps at 1 domain, `free`
// is post-trial read-only, and MSP-only entitlement stays enterprise-only.
// Any price change without a lockstep edit of policy + registry + this file
// fails CI. Requires Node 24+. CI-blocking.
//
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const eng = (f) => pathToFileURL(path.join(root, "workers", "scan-api", "src", "engines", f)).href;

const registry = await import(eng("pricing-registry.js"));
const ent = await import(eng("entitlements.js"));
const stripe = await import(eng("stripe.js"));

const { CANONICAL_PLANS, TRIAL_SPEC, expectedCheckoutAmountPence, penceToGbp } = registry;
const { BILLING_PLAN_METADATA, PLAN_LIMITS, getEffectiveDomainLimit, hasFeatureEntitlement, normalizePlan } = ent;
const { getPlanFromStripePriceId, buildMergedStripePriceMap, verifyStripePriceMatchesPolicy } = stripe;

let pass = 0, fail = 0;
const ok = (name, cond) => { cond ? pass++ : fail++; if (!cond) console.log("FAIL " + name); };

// ── Locked ladder (docs/PRICING-POLICY.md §2/§3) — exact pence ───────────────
ok("trial is £0", CANONICAL_PLANS.free.monthly_pence === 0 && CANONICAL_PLANS.free.annual_pence === 0);
ok("starter £9.99/mo", CANONICAL_PLANS.starter.monthly_pence === 999);
ok("professional £19.99/mo", CANONICAL_PLANS.professional.monthly_pence === 1999);
ok("business £49.99/mo", CANONICAL_PLANS.business.monthly_pence === 4999);
ok("MSP base £99.99/mo", CANONICAL_PLANS.enterprise.base_monthly_pence === 9999);
ok("MSP per-domain £3/mo", CANONICAL_PLANS.enterprise.per_domain_monthly_pence === 300);
ok("MSP minimum billed quantity 10", CANONICAL_PLANS.enterprise.min_billed_domains === 10);
ok("MSP monthly floor £129.99", CANONICAL_PLANS.enterprise.floor_monthly_pence === 12999);
ok("MSP annual floor £1,299.90", CANONICAL_PLANS.enterprise.floor_annual_pence === 129990);
ok("business overage +£3/mo per domain", CANONICAL_PLANS.business.additional_domain_monthly_pence === 300);
ok("business overage annual £30/domain", CANONICAL_PLANS.business.additional_domain_annual_pence === 3000);
ok("business hard cap 25", CANONICAL_PLANS.business.domain_hard_cap === 25);

// Annual = EXACTLY 10 × monthly (policy §3: exact figures, never a recomputed %)
for (const key of ["starter", "professional", "business"]) {
  ok(`${key} annual = 10 × monthly`, CANONICAL_PLANS[key].annual_pence === CANONICAL_PLANS[key].monthly_pence * 10);
}
ok("MSP annual base = 10 × monthly base", CANONICAL_PLANS.enterprise.base_annual_pence === CANONICAL_PLANS.enterprise.base_monthly_pence * 10);

// ── Included-domain ladder (policy §2/§6) ────────────────────────────────────
ok("trial/free 1 domain", CANONICAL_PLANS.free.included_domains === 1);
ok("starter 1 domain", CANONICAL_PLANS.starter.included_domains === 1);
ok("professional 3 domains", CANONICAL_PLANS.professional.included_domains === 3);
ok("business 10 included domains", CANONICAL_PLANS.business.included_domains === 10);

// ── Trial spec (policy §4) ───────────────────────────────────────────────────
ok("trial 14 days", TRIAL_SPEC.duration_days === 14);
ok("trial 1 domain", TRIAL_SPEC.domains === 1);
ok("trial takes no card", TRIAL_SPEC.card_required === false);
ok("trial caps a professional-featured trial at 1 domain", getEffectiveDomainLimit("professional", true) === 1);
ok("non-trial professional domain limit is 3", getEffectiveDomainLimit("professional", false) === 3);

// ── Derived runtime tables agree with the registry ───────────────────────────
ok("metadata starter £9.99", BILLING_PLAN_METADATA.starter.monthly_gbp === 9.99);
ok("metadata professional £19.99", BILLING_PLAN_METADATA.professional.monthly_gbp === 19.99);
ok("metadata business £49.99", BILLING_PLAN_METADATA.business.monthly_gbp === 49.99);
ok("metadata starter annual £99.90", BILLING_PLAN_METADATA.starter.annual_gbp === 99.9);
ok("metadata professional annual £199.90", BILLING_PLAN_METADATA.professional.annual_gbp === 199.9);
ok("metadata business annual £499.90", BILLING_PLAN_METADATA.business.annual_gbp === 499.9);
ok("metadata MSP has no flat monthly price", BILLING_PLAN_METADATA.enterprise.monthly_gbp === null);
ok("metadata MSP base £99.99", BILLING_PLAN_METADATA.enterprise.pricing_model.base_monthly_gbp === 99.99);
ok("metadata MSP floor £129.99", BILLING_PLAN_METADATA.enterprise.pricing_model.floor_monthly_gbp === 129.99);
ok("metadata trial block on free", BILLING_PLAN_METADATA.free.pricing_model.trial?.duration_days === 14);
ok("free plan display name is the trial", BILLING_PLAN_METADATA.free.name === "14-Day Full Trial");
ok("enterprise display name is MSP", BILLING_PLAN_METADATA.enterprise.name === "MSP");
ok("checkout enabled exactly for starter/professional/business",
  ["starter", "professional", "business"].every((k) => BILLING_PLAN_METADATA[k].checkout_enabled === true) &&
  ["free", "enterprise"].every((k) => BILLING_PLAN_METADATA[k].checkout_enabled === false));

ok("PLAN_LIMITS domains ladder 1/1/3/10", PLAN_LIMITS.free.domains === 1 && PLAN_LIMITS.starter.domains === 1 && PLAN_LIMITS.professional.domains === 3 && PLAN_LIMITS.business.domains === 10);
ok("free is post-trial read-only: no new scans", PLAN_LIMITS.free.scans_per_month === 0);
ok("free is post-trial read-only: no scheduled scans", PLAN_LIMITS.free.scheduled_scans === 0);
ok("free is post-trial read-only: no new reports", PLAN_LIMITS.free.reports_per_month === 0);

// No plan appears twice; every canonical plan appears exactly once.
const keys = Object.keys(CANONICAL_PLANS);
ok("exactly the five canonical plan keys", JSON.stringify(keys.slice().sort()) === JSON.stringify(["business", "enterprise", "free", "professional", "starter"]));
ok("metadata covers the same five keys", JSON.stringify(Object.keys(BILLING_PLAN_METADATA).slice().sort()) === JSON.stringify(keys.slice().sort()));

// ── MSP entitlement stays explicit + enterprise-only ─────────────────────────
ok("msp_dashboard entitlement on enterprise", hasFeatureEntitlement("enterprise", "msp_dashboard") === true);
ok("msp_dashboard NOT granted to business", hasFeatureEntitlement("business", "msp_dashboard") === false);
ok("msp_dashboard NOT granted to professional", hasFeatureEntitlement("professional", "msp_dashboard") === false);
ok("unknown plan normalises to free (fail closed)", normalizePlan("platinum") === "free");

// ── Checkout amount expectations ─────────────────────────────────────────────
ok("expected starter monthly charge 999p", expectedCheckoutAmountPence("starter", "monthly") === 999);
ok("expected professional annual charge 19990p", expectedCheckoutAmountPence("professional", "annual") === 19990);
ok("free is never checkout-charged", expectedCheckoutAmountPence("free", "monthly") === null);
ok("MSP is never self-serve checkout-charged", expectedCheckoutAmountPence("enterprise", "monthly") === null);
ok("penceToGbp exact 2dp", penceToGbp(999) === 9.99 && penceToGbp(129990) === 1299.9);

// ── Price-ID mapping: key-based, merged, fail-closed ─────────────────────────
const envIndividual = { STRIPE_PRO_MONTHLY_PRICE_ID: "price_pro_m", STRIPE_SECRET_KEY: "sk_test_x" };
ok("merged map honours individual env vars (webhook reverse path)",
  buildMergedStripePriceMap(envIndividual).professional_monthly === "price_pro_m");
ok("reverse lookup maps the individual-var price to professional",
  getPlanFromStripePriceId(envIndividual, "price_pro_m", "starter") === "professional");
const envJson = { STRIPE_PRICE_MAP: JSON.stringify({ starter_monthly: "price_s", business_annual: "price_ba" }) };
ok("reverse lookup via JSON map", getPlanFromStripePriceId(envJson, "price_ba", null) === "business");
ok("individual vars take precedence over JSON map",
  buildMergedStripePriceMap({ ...envJson, STRIPE_STARTER_MONTHLY_PRICE_ID: "price_override" }).starter_monthly === "price_override");
ok("UNKNOWN price fails CLOSED — never the metadata fallback",
  getPlanFromStripePriceId(envJson, "price_UNKNOWN", "business") === null);
ok("no price at all → server-authored metadata fallback allowed",
  getPlanFromStripePriceId(envJson, null, "professional") === "professional");
ok("mapping is keyed by stable plan keys, not display names",
  getPlanFromStripePriceId({ STRIPE_PRICE_MAP: JSON.stringify({ "MSP_monthly": "price_x" }) }, "price_x", null) === "free" ||
  getPlanFromStripePriceId({ STRIPE_PRICE_MAP: JSON.stringify({ "MSP_monthly": "price_x" }) }, "price_x", null) === null);

// ── Checkout price-policy guard (mocked Stripe read) ─────────────────────────
const realFetch = globalThis.fetch;
const mockPrice = (price) => { globalThis.fetch = async () => ({ ok: true, json: async () => price }); };
const envStripe = { STRIPE_SECRET_KEY: "sk_test_x" };

mockPrice({ id: "p1", currency: "gbp", unit_amount: 999, active: true, recurring: { interval: "month" } });
ok("policy-matching price passes", (await verifyStripePriceMatchesPolicy(envStripe, "starter", "monthly", "p1")).ok === true);

mockPrice({ id: "p2", currency: "gbp", unit_amount: 2900, active: true, recurring: { interval: "month" } });
ok("legacy £29 price REFUSED for starter checkout", (await verifyStripePriceMatchesPolicy(envStripe, "starter", "monthly", "p2")).ok === false);

// Swapped mapping: professional checkout resolving the starter price must refuse.
mockPrice({ id: "p3", currency: "gbp", unit_amount: 999, active: true, recurring: { interval: "month" } });
ok("swapped price mapping REFUSED (starter amount on professional checkout)", (await verifyStripePriceMatchesPolicy(envStripe, "professional", "monthly", "p3")).ok === false);

mockPrice({ id: "p4", currency: "usd", unit_amount: 999, active: true, recurring: { interval: "month" } });
ok("non-GBP price refused", (await verifyStripePriceMatchesPolicy(envStripe, "starter", "monthly", "p4")).ok === false);

mockPrice({ id: "p5", currency: "gbp", unit_amount: 999, active: true, recurring: { interval: "year" } });
ok("monthly checkout refuses an annual-interval price", (await verifyStripePriceMatchesPolicy(envStripe, "starter", "monthly", "p5")).ok === false);

mockPrice({ id: "p6", currency: "gbp", unit_amount: 9990, active: true, recurring: { interval: "year" } });
ok("annual checkout passes the exact ×10 figure", (await verifyStripePriceMatchesPolicy(envStripe, "starter", "annual", "p6")).ok === true);

mockPrice({ id: "p7", currency: "gbp", unit_amount: 999, active: false, recurring: { interval: "month" } });
ok("inactive price refused", (await verifyStripePriceMatchesPolicy(envStripe, "starter", "monthly", "p7")).ok === false);

globalThis.fetch = async () => { throw new Error("network down"); };
ok("Stripe unreachable → checkout guard fails closed", (await verifyStripePriceMatchesPolicy(envStripe, "starter", "monthly", "p8")).ok === false);
globalThis.fetch = realFetch;

console.log(`\nPricing policy parity: ${pass}/${pass + fail} passed`);
if (fail) { console.error("pricing-policy-parity validation FAILED"); process.exit(1); }
console.log("pricing-policy-parity validation passed");
