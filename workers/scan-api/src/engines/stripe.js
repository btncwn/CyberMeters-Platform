// ── Stripe billing integration ──
// Stripe price-map + config validation, webhook signature verification (HMAC-SHA256),
// subscription/invoice object parsing, subscription-state upsert, and the checkout/subscription/
// invoice webhook event handlers + billing audit-event writer. Extracted verbatim from index.js
// (monolith decomposition, Phase 1c). Price-map/signature-parsing/crypto helpers +
// upsertStripeSubscriptionState are module-internal.
import { createAuditEvent, createNotificationEvent } from "../lib/events.js";
import { createId } from "../lib/util.js";
import { escapeEmailHtml, getEmailFrontendOrigin, sendCustomerEmail } from "../lib/lifecycle-email.js";
import { getPaymentGraceState, lineageGraceAnchor, normalizeBillingInterval, normalizePlan } from "./entitlements.js";
import { expectedCheckoutAmountPence } from "./pricing-registry.js";
import { isSubscriptionActive } from "./subscription-state.js";

function parseStripePriceMap(env) {
  const raw = env?.STRIPE_PRICE_MAP;
  if (!raw) return { ok: false, error: "missing_stripe_price_map", map: {} };
  try {
    const parsed = JSON.parse(raw);
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
      return { ok: false, error: "invalid_stripe_price_map", map: {} };
    }
    return { ok: true, error: null, map: parsed };
  } catch {
    return { ok: false, error: "invalid_stripe_price_map", map: {} };
  }
}

// Build a price map from individual env vars (Option A).
// Key format matches STRIPE_PRICE_MAP: "{plan}_{interval}" → price_id.
// Individual vars take precedence over STRIPE_PRICE_MAP if both are set.
function buildStripePriceMapFromIndividualVars(env) {
  const map = {};
  const mappings = [
    ["STRIPE_STARTER_MONTHLY_PRICE_ID",  "starter_monthly"],
    ["STRIPE_STARTER_ANNUAL_PRICE_ID",   "starter_annual"],
    ["STRIPE_PRO_MONTHLY_PRICE_ID",      "professional_monthly"],
    ["STRIPE_PRO_ANNUAL_PRICE_ID",       "professional_annual"],
    ["STRIPE_BUSINESS_MONTHLY_PRICE_ID", "business_monthly"],
    ["STRIPE_BUSINESS_ANNUAL_PRICE_ID",  "business_annual"],
    // Accepted aliases for the secret names configured in production
    // (PROFESSIONAL vs PRO, YEARLY vs ANNUAL). A set alias fills the same key.
    ["STRIPE_STARTER_YEARLY_PRICE_ID",       "starter_annual"],
    ["STRIPE_PROFESSIONAL_MONTHLY_PRICE_ID", "professional_monthly"],
    ["STRIPE_PROFESSIONAL_YEARLY_PRICE_ID",  "professional_annual"],
    ["STRIPE_PROFESSIONAL_ANNUAL_PRICE_ID",  "professional_annual"],
    ["STRIPE_BUSINESS_YEARLY_PRICE_ID",      "business_annual"],
  ];
  for (const [envVar, key] of mappings) {
    if (env?.[envVar]) map[key] = env[envVar];
  }
  return map;
}

export function validateStripeBillingConfig(env) {
  const missing = [];
  if (!env?.STRIPE_SECRET_KEY) missing.push("STRIPE_SECRET_KEY");
  if (!env?.STRIPE_PRICE_MAP) missing.push("STRIPE_PRICE_MAP");
  const priceMap = parseStripePriceMap(env);
  if (missing.length > 0) return { ok: false, error: "missing_stripe_config", missing, priceMap: {} };
  if (!priceMap.ok) return { ok: false, error: priceMap.error, missing: [], priceMap: {} };
  return { ok: true, error: null, missing: [], priceMap: priceMap.map };
}

export function validateStripeSecretConfig(env) {
  if (!env?.STRIPE_SECRET_KEY) {
    return { ok: false, error: "missing_stripe_config", missing: ["STRIPE_SECRET_KEY"] };
  }
  return { ok: true, error: null, missing: [] };
}

export function getStripePriceIdForPlan(env, plan, interval = "monthly") {
  const normalizedPlan = normalizePlan(plan);
  const normalizedInterval = normalizeBillingInterval(interval);
  if (normalizedPlan === "free" || normalizedPlan === "enterprise") {
    return { ok: false, error: "plan_not_checkout_eligible", price_id: null };
  }
  if (!env?.STRIPE_SECRET_KEY) {
    return { ok: false, error: "missing_stripe_config", missing: ["STRIPE_SECRET_KEY"], price_id: null };
  }

  const key = `${normalizedPlan}_${normalizedInterval}`;

  // Option A: individual env vars take precedence over STRIPE_PRICE_MAP JSON.
  const individualMap = buildStripePriceMapFromIndividualVars(env);
  if (individualMap[key]) {
    return { ok: true, error: null, missing: [], price_id: individualMap[key] };
  }

  // Option B: STRIPE_PRICE_MAP JSON fallback.
  // STRIPE_PRICE_MAP uses explicit composite keys: "{plan}_{interval}" → price_id.
  // Example: { "starter_monthly": "price_xxx", "professional_annual": "price_yyy" }
  const config = validateStripeBillingConfig(env);
  if (!config.ok) return { ok: false, error: config.error, missing: config.missing, price_id: null };

  const priceId = config.priceMap[key];
  if (!priceId || typeof priceId !== "string") {
    return { ok: false, error: "missing_stripe_price", missing: [key], price_id: null };
  }
  return { ok: true, error: null, missing: [], price_id: priceId };
}

export function validateStripeWebhookConfig(env) {
  if (!env?.STRIPE_WEBHOOK_SECRET) {
    return { ok: false, error: "missing_stripe_webhook_secret", missing: ["STRIPE_WEBHOOK_SECRET"] };
  }
  return { ok: true, error: null, missing: [] };
}

function parseStripeSignatureHeader(header) {
  const parts = String(header || "").split(",").map((part) => part.trim()).filter(Boolean);
  const timestampPart = parts.find((part) => part.startsWith("t="));
  const timestamp = timestampPart ? Number(timestampPart.slice(2)) : NaN;
  const signatures = parts
    .filter((part) => part.startsWith("v1="))
    .map((part) => part.slice(3))
    .filter(Boolean);
  return { timestamp, signatures };
}

function bufferToHex(buffer) {
  return Array.from(new Uint8Array(buffer))
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
}

function timingSafeEqualHex(a, b) {
  if (typeof a !== "string" || typeof b !== "string") return false;
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return diff === 0;
}

async function hmacSha256Hex(secret, payload) {
  const encoder = new TextEncoder();
  const key = await crypto.subtle.importKey(
    "raw",
    encoder.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const signature = await crypto.subtle.sign("HMAC", key, encoder.encode(payload));
  return bufferToHex(signature);
}

export async function verifyStripeWebhookSignature(rawBody, signatureHeader, webhookSecret) {
  const { timestamp, signatures } = parseStripeSignatureHeader(signatureHeader);
  if (!Number.isFinite(timestamp) || signatures.length === 0) {
    return { ok: false, error: "invalid_signature_header" };
  }

  const toleranceSeconds = 300;
  const ageSeconds = Math.abs(Math.floor(Date.now() / 1000) - timestamp);
  if (ageSeconds > toleranceSeconds) {
    return { ok: false, error: "signature_timestamp_outside_tolerance" };
  }

  const expected = await hmacSha256Hex(webhookSecret, `${timestamp}.${rawBody}`);
  const matched = signatures.some((signature) => timingSafeEqualHex(expected, signature));
  return matched ? { ok: true, error: null } : { ok: false, error: "invalid_signature" };
}

export function stripeUnixToIso(value) {
  const seconds = Number(value);
  if (!Number.isFinite(seconds) || seconds <= 0) return null;
  return new Date(seconds * 1000).toISOString();
}

export function getStripeObjectId(value) {
  if (!value) return null;
  if (typeof value === "string") return value;
  if (typeof value === "object" && typeof value.id === "string") return value.id;
  return null;
}

// Basil and later moved the invoice's subscription into a typed parent.
// Keep older webhook payloads and expanded Stripe objects compatible.
export function getStripeInvoiceSubscriptionId(invoice) {
  return getStripeObjectId(invoice?.subscription)
    || (invoice?.parent?.type === "subscription_details"
      ? getStripeObjectId(invoice.parent.subscription_details?.subscription)
      : null);
}

// Merged forward map — the ONE price-ID authority for both directions.
// Individual env vars (Option A) overlay the STRIPE_PRICE_MAP JSON (Option B),
// exactly matching getStripePriceIdForPlan's checkout-time precedence. Before
// this, the webhook reverse lookup read ONLY the JSON map: a deployment
// configured through individual vars mapped every subscription event through
// the metadata fallback instead of through the price the customer actually pays.
export function buildMergedStripePriceMap(env) {
  const json = parseStripePriceMap(env);
  return { ...(json.ok ? json.map : {}), ...buildStripePriceMapFromIndividualVars(env) };
}

// Base subscription item. Multi-item subscriptions (e.g. base plan +
// per-domain overage item): the BASE item is the one whose price maps to a
// canonical plan — never blindly items[0], whose ordering Stripe does not
// guarantee.
export function getStripeBaseSubscriptionItem(subscription, env = null) {
  const items = subscription?.items?.data;
  if (!Array.isArray(items) || items.length === 0) return null;
  if (items.length > 1 && env) {
    const merged = buildMergedStripePriceMap(env);
    const mappedIds = new Set(Object.values(merged));
    const base = items.find((it) => it?.price?.id && mappedIds.has(it.price.id));
    if (base?.price) return base;
  }
  return items[0];
}

export function getStripeSubscriptionPrice(subscription, env = null) {
  const item = getStripeBaseSubscriptionItem(subscription, env);
  return item?.price ?? subscription?.plan ?? null;
}

// Stripe API 2025-03-31 (Basil) and later moved current_period_start/end off
// the subscription object onto each subscription item, and this deployment
// does not pin a Stripe-Version — payloads arrive at the account's default
// API version. Read the top-level fields first (older API versions still send
// them), then fall back to the BASE plan item's period, so the entitlement
// window is never silently persisted as NULL on a newer API version.
export function getStripeSubscriptionPeriod(subscription, env = null) {
  const item = getStripeBaseSubscriptionItem(subscription, env);
  return {
    start: stripeUnixToIso(subscription?.current_period_start) ?? stripeUnixToIso(item?.current_period_start),
    end: stripeUnixToIso(subscription?.current_period_end) ?? stripeUnixToIso(item?.current_period_end),
  };
}

export function getPlanFromStripePriceId(env, priceId, fallbackPlan = null) {
  const fallback = fallbackPlan ? normalizePlan(fallbackPlan) : null;
  // No price on the event (e.g. checkout.session.completed) → the server-authored
  // checkout metadata is the only plan source and remains acceptable.
  if (!priceId) return fallback;
  const merged = buildMergedStripePriceMap(env);
  // Reverse lookup over the merged map: find the key whose value matches priceId.
  const entry = Object.entries(merged).find(([, pid]) => pid === priceId);
  // A PRESENT but UNMAPPED price fails CLOSED (null — no plan granted), never
  // through the metadata fallback: metadata reflects what checkout once set,
  // not what the subscription now charges (e.g. a portal-side price change).
  if (!entry) return null;
  // Key format: "{plan}_{interval}" — plan is everything before the last underscore.
  const planPart = entry[0].replace(/_[^_]+$/, "");
  return normalizePlan(planPart) || null;
}

// verifyStripePriceMatchesPolicy — checkout guard. Reads the resolved price
// from Stripe and refuses the session unless it charges EXACTLY what the
// canonical pricing policy states for (plan, interval): GBP, recurring on the
// right interval, unit_amount to the penny, and active. This is the fail-closed
// link between the pricing cards and the card charge: a stale or mistyped
// Stripe price can never sell a number the policy does not state.
export async function verifyStripePriceMatchesPolicy(env, plan, interval, priceId) {
  const expectedPence = expectedCheckoutAmountPence(normalizePlan(plan), normalizeBillingInterval(interval));
  if (!expectedPence) return { ok: false, error: "plan_not_checkout_eligible" };
  let price;
  try {
    const res = await fetch(`https://api.stripe.com/v1/prices/${encodeURIComponent(priceId)}`, {
      headers: { "Authorization": `Bearer ${env.STRIPE_SECRET_KEY}` },
    });
    price = await res.json();
    if (!res.ok) return { ok: false, error: "stripe_price_lookup_failed" };
  } catch {
    return { ok: false, error: "stripe_price_lookup_failed" };
  }
  const expectedInterval = normalizeBillingInterval(interval) === "annual" ? "year" : "month";
  const mismatches = [];
  if (price?.currency !== "gbp") mismatches.push("currency");
  if (price?.recurring?.interval !== expectedInterval) mismatches.push("interval");
  if (price?.unit_amount !== expectedPence) mismatches.push("amount");
  if (price?.active === false) mismatches.push("inactive");
  if (mismatches.length > 0) {
    console.error("[stripe_price_policy_mismatch]", {
      plan: normalizePlan(plan), interval: normalizeBillingInterval(interval),
      price_id: priceId, expected_pence: expectedPence,
      actual_pence: price?.unit_amount ?? null, actual_currency: price?.currency ?? null,
      actual_interval: price?.recurring?.interval ?? null, mismatches,
    });
    return { ok: false, error: "stripe_price_policy_mismatch", mismatches };
  }
  return { ok: true, error: null };
}

// ── B2: checkout consent (founder-approved 21 Jul 2026) ──────────────────────
// Terms acceptance + immediate-start consent collected ON the Stripe Checkout
// page. consent_collection.terms_of_service='required' makes Stripe render a
// mandatory Terms checkbox (the ToS URL comes from the Stripe account's public
// business settings — a founder dashboard action); the custom_text message
// makes the immediate-start / 14-day cooling-off waiver explicit next to it.
// Stripe records the acceptance on the session (session.consent) — surfaced in
// our webhook audit trail. The wording states ONLY the approved policy: the
// service starts immediately, the consumer 14-day cancellation right is given
// up, prepaid fees are non-refundable except where required by law, and the
// free 14-day trial exists to try first. No rights beyond that are offered.
export const CHECKOUT_IMMEDIATE_START_CONSENT_TEXT =
  "By subscribing you agree to the CyberMeters Terms of Service and request that the " +
  "digital service starts immediately. Because the service begins straight away, you " +
  "give up the 14-day consumer cancellation (cooling-off) right, and prepaid fees are " +
  "non-refundable except where required by law. The free 14-day trial lets you try " +
  "CyberMeters before paying.";

export function applyCheckoutConsentParams(params) {
  params.set("consent_collection[terms_of_service]", "required");
  params.set("custom_text[terms_of_service_acceptance][message]", CHECKOUT_IMMEDIATE_START_CONSENT_TEXT);
  return params;
}

// ── B3: portal-only plan changes (founder-approved 21 Jul 2026) ──────────────
// A subscription-mode Checkout Session ALWAYS creates a NEW Stripe
// subscription — it never switches an existing one, and nothing in the webhook
// chain cancels a prior subscription. So a fresh checkout by a customer who
// already has an active paid Stripe subscription would stack a SECOND live
// subscription and charge them for both (our entitlement resolver would pick
// one row deterministically, but Stripe would bill both). Plan changes for
// such customers must therefore go through the Stripe billing portal, which
// switches the price on the EXISTING subscription and prorates cleanly.
//
// True only for a live PAID Stripe-bound subscription (active, or past_due
// inside the payment-grace window). Local trial rows and manual/founder rows
// carry no stripe_subscription_id and keep the fresh-checkout path; a
// Stripe customer id is also required — without one the portal cannot open.
export function shouldRoutePlanChangeToPortal(sub) {
  if (!sub) return false;
  if (!sub.stripe_customer_id || !sub.stripe_subscription_id) return false;
  return isSubscriptionActive(sub) || getPaymentGraceState(sub).active;
}

// Our own row normally knows a customer is already billed (see
// shouldRoutePlanChangeToPortal). When a webhook has not been applied yet it
// cannot, so the checkout also asks Stripe before creating another
// subscription. `incomplete` (first payment still pending or declined) is not
// a billed subscription and must not block a retry with another card.
const BILLED_STRIPE_SUBSCRIPTION_STATUSES = new Set(["active", "trialing", "past_due", "unpaid"]);

// Looks up by the stored Stripe customer, or — when no webhook has stored one
// yet — by the account email the checkout gave Stripe. Returns the billed
// subscription and its customer so the caller can open that customer's portal.
export async function findBilledStripeSubscription(env, { customerId = null, email = null } = {}) {
  const auth = { headers: { "Authorization": `Bearer ${env.STRIPE_SECRET_KEY}` } };
  const billedIn = (list) => (Array.isArray(list) ? list : [])
    .find((sub) => BILLED_STRIPE_SUBSCRIPTION_STATUSES.has(String(sub?.status || "")));
  try {
    if (customerId) {
      const res = await fetch(
        `https://api.stripe.com/v1/subscriptions?customer=${encodeURIComponent(customerId)}&status=all&limit=20`, auth);
      const body = await res.json().catch(() => null);
      if (!res.ok || !Array.isArray(body?.data)) return { ok: false, subscription: null };
      const billed = billedIn(body.data);
      return { ok: true, subscription: billed ? { id: billed.id, status: billed.status, customer: customerId } : null };
    }
    if (email) {
      const res = await fetch(
        `https://api.stripe.com/v1/customers?email=${encodeURIComponent(email)}&limit=10&expand[]=data.subscriptions`, auth);
      const body = await res.json().catch(() => null);
      if (!res.ok || !Array.isArray(body?.data)) return { ok: false, subscription: null };
      for (const customer of body.data) {
        const billed = billedIn(customer?.subscriptions?.data);
        if (billed && customer?.id) return { ok: true, subscription: { id: billed.id, status: billed.status, customer: customer.id } };
      }
      return { ok: true, subscription: null };
    }
    return { ok: true, subscription: null };
  } catch {
    return { ok: false, subscription: null };
  }
}

export function getBillingIntervalFromStripeSubscription(subscription, fallbackInterval = "monthly") {
  const price = getStripeSubscriptionPrice(subscription);
  const interval = price?.recurring?.interval;
  if (interval === "year") return "annual";
  if (interval === "month") return "monthly";
  return normalizeBillingInterval(fallbackInterval);
}

export function normalizeStripeSubscriptionStatus(status) {
  const value = String(status || "").trim().toLowerCase();
  return value || "incomplete";
}

function canceledSubscriptionMarkerId(stripeSubscriptionId) {
  return `stripe_canceled_subscription:${stripeSubscriptionId}`;
}

async function hasCanceledSubscriptionMarker(env, stripeSubscriptionId) {
  if (!stripeSubscriptionId) return false;
  return Boolean(await env.cybermeters_db
    .prepare("SELECT 1 FROM stripe_processed_events WHERE id = ? AND event_type = 'subscription_canceled' AND status = 'completed' LIMIT 1")
    .bind(canceledSubscriptionMarkerId(stripeSubscriptionId))
    .first());
}

// Most specific identity first. A Stripe subscription id names exactly one
// billing lineage and a Stripe customer id is UNIQUE across rows, so either
// identifies the row Stripe is describing. The owner is only a fallback: an
// owner can hold several historical rows, and picking an arbitrary one of them
// made a returning customer's checkout copy their customer id onto a second
// row, hit the unique index and fail — payment taken, plan never activated.
// Within an owner the row for the event's workspace wins, then the newest.
export async function findSubscriptionRowId(env, { ownerUserId = null, stripeSubscriptionId = null, stripeCustomerId = null, workspaceId = null } = {}) {
  if (stripeSubscriptionId) {
    const row = await env.cybermeters_db
      .prepare("SELECT id FROM subscriptions WHERE stripe_subscription_id = ? LIMIT 1")
      .bind(stripeSubscriptionId)
      .first();
    if (row?.id) return row.id;
  }

  if (stripeCustomerId) {
    const row = await env.cybermeters_db
      .prepare("SELECT id FROM subscriptions WHERE stripe_customer_id = ? LIMIT 1")
      .bind(stripeCustomerId)
      .first();
    if (row?.id) return row.id;
  }

  if (ownerUserId) {
    // Strict identity (C-49 F13): the owner fallback never takes a row that
    // belongs to a DIFFERENT Stripe customer — that row is another billing
    // lineage. Rows with no customer yet (a trial or free row) stay reachable.
    const row = await env.cybermeters_db
      .prepare(
        `SELECT id FROM subscriptions
         WHERE owner_user_id = ?
           AND (? IS NULL OR stripe_customer_id IS NULL OR stripe_customer_id = ?)
         ORDER BY CASE WHEN workspace_id = ? THEN 0 ELSE 1 END,
                  COALESCE(updated_at, created_at) DESC,
                  id DESC
         LIMIT 1`
      )
      .bind(ownerUserId, stripeCustomerId, stripeCustomerId, workspaceId)
      .first();
    if (row?.id) return row.id;
  }

  return null;
}

async function upsertStripeSubscriptionState(env, state) {
  const ownerUserId = state.owner_user_id || null;
  const workspaceId = state.workspace_id || null;
  const stripeCustomerId = state.stripe_customer_id || null;
  const stripeSubscriptionId = state.stripe_subscription_id || null;
  const cancellationMarkerId = state.cancellation_marker_id || null;
  const rowId = await findSubscriptionRowId(env, {
    ownerUserId,
    stripeSubscriptionId,
    stripeCustomerId,
    workspaceId,
  });

  if (rowId) {
    const cancelAtPeriodEnd = state.cancel_at_period_end != null
      ? (state.cancel_at_period_end ? 1 : 0)
      : null;
    // Out-of-order delivery (Q3 item 13, C-49): every state written here is
    // Stripe's CURRENT view of the lineage the row reflects, re-read by
    // syncStripeSubscription — never an event payload — so the period is
    // written as Stripe states it (a lineage switch may legitimately move it).
    const cpEnd = state.current_period_end || null;
    // state.plan === null means the event's price could not be mapped to a
    // canonical plan (fail-closed): payment/lifecycle state still applies, but
    // the stored plan is left untouched — an unknown price never grants or
    // changes an entitlement.
    //
    // subscription_status is the canonical lifecycle column; the legacy
    // `status` column is written in LOCKSTEP (same value) by every webhook
    // writer so the two can never diverge — a June trial row kept
    // status='trialing' after a paid checkout because only
    // subscription_status was updated (21 Jul 2026 B2/B3 acceptance
    // evidence), misleading any reader of the raw column.
    await env.cybermeters_db
      .prepare(
        `UPDATE subscriptions
         SET plan = COALESCE(?, plan),
             billing_interval = ?,
             subscription_status = ?,
             status = ?,
             stripe_customer_id = COALESCE(?, stripe_customer_id),
             stripe_subscription_id = COALESCE(?, stripe_subscription_id),
             stripe_price_id = COALESCE(?, stripe_price_id),
             current_period_start = COALESCE(?, current_period_start),
             current_period_end = COALESCE(?, current_period_end),
             cancel_at_period_end = COALESCE(?, cancel_at_period_end),
             workspace_id = CASE
               WHEN ? IS NOT NULL AND NOT EXISTS (
                 SELECT 1 FROM subscriptions other WHERE other.workspace_id = ? AND other.id <> subscriptions.id
               ) THEN ?
               ELSE workspace_id END,
             updated_at = datetime('now')
         WHERE id = ?
           AND (? = 0 OR stripe_subscription_id IS NULL OR stripe_subscription_id <> ?)
           AND NOT EXISTS (
             SELECT 1 FROM stripe_processed_events
              WHERE id = ? AND event_type = 'subscription_canceled' AND status = 'completed'
           )`
      )
      .bind(
        state.plan === null ? null : normalizePlan(state.plan),
        normalizeBillingInterval(state.billing_interval),
        normalizeStripeSubscriptionStatus(state.subscription_status),
        normalizeStripeSubscriptionStatus(state.subscription_status),
        stripeCustomerId,
        stripeSubscriptionId,
        state.stripe_price_id || null,
        state.current_period_start || null,
        cpEnd,
        cancelAtPeriodEnd,
        // The hand-made production table can enforce one row per workspace
        // (it predates the migrations that describe it). A row is moved to
        // the event's workspace only when that workspace has no other row;
        // otherwise the move would break that rule and fail every retry.
        // Entitlement is resolved per owner, so the row's workspace never
        // changes what the customer gets.
        workspaceId, workspaceId, workspaceId,
        rowId,
        state.preserve_existing_subscription_state ? 1 : 0,
        stripeSubscriptionId,
        cancellationMarkerId
      )
      .run();
    return rowId;
  }

  // Guard: if workspace_id is null and no existing row was found, the INSERT would
  // violate the NOT NULL constraint on the production subscriptions table.
  // Return null and let the webhook handler return 200 to Stripe — this event
  // cannot be safely mapped without a workspace context.
  if (!ownerUserId) return null;
  if (!workspaceId) {
    console.warn("[stripe_webhook_workspace_unresolved] Skipping INSERT — workspace_id is null and no existing row found", {
      owner_user_id: ownerUserId,
      stripe_subscription_id: stripeSubscriptionId,
      stripe_customer_id: stripeCustomerId,
    });
    return null;
  }

  // P2-D: Before inserting a new row, check whether a local trial row already
  // exists for this workspace (no stripe_subscription_id yet). If so, UPDATE it
  // rather than INSERT to avoid a duplicate trialing + active pair.
  if (workspaceId) {
    const trialRow = await env.cybermeters_db
      .prepare(
        `SELECT id FROM subscriptions
         WHERE workspace_id = ?
           AND stripe_subscription_id IS NULL
           AND subscription_status = 'trialing'
         LIMIT 1`
      )
      .bind(workspaceId)
      .first()
      .catch(() => null);

    if (trialRow?.id) {
      const cancelAtPeriodEndUpd = state.cancel_at_period_end != null
        ? (state.cancel_at_period_end ? 1 : 0)
        : null;
      await env.cybermeters_db
        .prepare(
          `UPDATE subscriptions
           SET plan = COALESCE(?, plan),
               billing_interval = ?,
               subscription_status = ?,
               status = ?,
               owner_user_id = COALESCE(?, owner_user_id),
               stripe_customer_id = COALESCE(?, stripe_customer_id),
               stripe_subscription_id = COALESCE(?, stripe_subscription_id),
               stripe_price_id = COALESCE(?, stripe_price_id),
               current_period_start = COALESCE(?, current_period_start),
               current_period_end = COALESCE(?, current_period_end),
               cancel_at_period_end = COALESCE(?, cancel_at_period_end),
               updated_at = datetime('now')
           WHERE id = ?
             AND (? = 0 OR stripe_subscription_id IS NULL OR stripe_subscription_id <> ?)
             AND NOT EXISTS (
               SELECT 1 FROM stripe_processed_events
                WHERE id = ? AND event_type = 'subscription_canceled' AND status = 'completed'
             )`
        )
        .bind(
          state.plan === null ? null : normalizePlan(state.plan),
          normalizeBillingInterval(state.billing_interval),
          normalizeStripeSubscriptionStatus(state.subscription_status),
          normalizeStripeSubscriptionStatus(state.subscription_status),
          ownerUserId,
          stripeCustomerId,
          stripeSubscriptionId,
          state.stripe_price_id || null,
          state.current_period_start || null,
          state.current_period_end || null,
          cancelAtPeriodEndUpd,
          trialRow.id,
          state.preserve_existing_subscription_state ? 1 : 0,
          stripeSubscriptionId,
          cancellationMarkerId
        )
        .run();
      return trialRow.id;
    }
  }

  const id = createId("sub");
  const cancelAtPeriodEndInsert = state.cancel_at_period_end != null
    ? (state.cancel_at_period_end ? 1 : 0)
    : 0;
  const insertResult = await env.cybermeters_db
    .prepare(
      `INSERT INTO subscriptions
         (id, owner_user_id, workspace_id, plan, billing_interval, subscription_status, status,
          stripe_customer_id, stripe_subscription_id, stripe_price_id,
          current_period_start, current_period_end, cancel_at_period_end,
          created_at, updated_at)
       SELECT ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'), datetime('now')
        WHERE NOT EXISTS (
          SELECT 1 FROM stripe_processed_events
           WHERE id = ? AND event_type = 'subscription_canceled' AND status = 'completed'
        )`
    )
    .bind(
      id,
      ownerUserId,
      workspaceId,
      normalizePlan(state.plan),
      normalizeBillingInterval(state.billing_interval),
      normalizeStripeSubscriptionStatus(state.subscription_status),
      normalizeStripeSubscriptionStatus(state.subscription_status),
      stripeCustomerId,
      stripeSubscriptionId,
      state.stripe_price_id || null,
      state.current_period_start || null,
      state.current_period_end || null,
      cancelAtPeriodEndInsert,
      cancellationMarkerId
    )
    .run();
  return Number(insertResult?.meta?.changes ?? insertResult?.changes ?? 0) === 1 ? id : null;
}

// ── Stripe subscription lineages (migration 139; billing P1 / Codex C-49) ────
//
// Stripe does not order webhook deliveries, so an event's own payload is never
// trusted for state: every subscription, invoice and checkout event that names
// a subscription FETCHES that subscription from Stripe (latest invoice
// expanded) and stores Stripe's current view per subscription id. The account
// `subscriptions` row — the one entitlements read — is then derived from the
// customer's best ENTITLED lineage. Consequences, by construction:
//   • an older/late event can only re-read today's truth (no ordering bugs);
//   • a cancelled lineage is terminal; only a new subscription id re-grants;
//   • the payment grace is anchored on Stripe's latest unpaid invoice creation
//     time, so a retried webhook never restarts it;
//   • one subscription's events never overwrite another subscription's state.
// A fetch failure throws: the route answers 500 and Stripe retries the event.
// A subscription Stripe does not know (404) changes nothing: never a reason to
// cancel (a wrong-mode key would otherwise cancel every customer).

const PLAN_RANK = Object.freeze({ free: 0, starter: 1, professional: 2, business: 3, enterprise: 4 });
const TERMINAL_STRIPE_STATUSES = new Set(["canceled", "incomplete_expired"]);
const nowIso = () => new Date(Date.now()).toISOString();

export async function fetchStripeSubscription(env, subscriptionId) {
  if (!env?.STRIPE_SECRET_KEY) throw new Error("stripe_secret_missing");
  const res = await fetch(
    `https://api.stripe.com/v1/subscriptions/${encodeURIComponent(subscriptionId)}?expand[]=latest_invoice`,
    { headers: { "Authorization": `Bearer ${env.STRIPE_SECRET_KEY}` } },
  );
  if (res.status === 404) return null;
  const body = await res.json().catch(() => null);
  if (!res.ok || body?.id !== subscriptionId) throw new Error(`stripe_subscription_fetch_failed:${res.status}`);
  return body;
}

// Pure: Stripe's subscription object → the lineage row (terminal stays terminal).
export function lineageFromStripeSubscription(env, sub, { previous = null, hint = {} } = {}) {
  const metadata = sub?.metadata || {};
  const priceId = getStripeSubscriptionPrice(sub, env)?.id || null;
  const period = getStripeSubscriptionPeriod(sub, env);
  const invoice = sub?.latest_invoice && typeof sub.latest_invoice === "object" ? sub.latest_invoice : null;
  const fetchedStatus = normalizeStripeSubscriptionStatus(sub?.status);
  const terminal = Boolean(previous?.terminal) || TERMINAL_STRIPE_STATUSES.has(fetchedStatus);
  return {
    stripe_subscription_id: sub.id,
    stripe_customer_id: getStripeObjectId(sub?.customer) || previous?.stripe_customer_id || null,
    // The account a lineage bills is fixed when it is first seen: metadata
    // never moves billing to another account (C-49 F14; no supported
    // billing-transfer policy exists).
    owner_user_id: previous?.owner_user_id || metadata.user_id || hint.owner_user_id || null,
    workspace_id: previous?.workspace_id || metadata.workspace_id || hint.workspace_id || null,
    // A terminal lineage never leaves cancelled, whatever a later read says.
    status: terminal ? "canceled" : fetchedStatus,
    // An unknown price never grants or changes a plan (fail closed).
    plan: getPlanFromStripePriceId(env, priceId, metadata.plan) ?? previous?.plan ?? null,
    stripe_price_id: priceId || previous?.stripe_price_id || null,
    billing_interval: getBillingIntervalFromStripeSubscription(sub, metadata.interval),
    current_period_start: period.start || previous?.current_period_start || null,
    current_period_end: period.end || previous?.current_period_end || null,
    cancel_at_period_end: sub?.cancel_at_period_end ? 1 : 0,
    latest_invoice_id: invoice?.id || (typeof sub?.latest_invoice === "string" ? sub.latest_invoice : null),
    latest_invoice_status: invoice?.status || null,
    latest_invoice_created: invoice?.created ? stripeUnixToIso(invoice.created) : null,
    latest_invoice_attempts: Number.isInteger(invoice?.attempt_count) ? invoice.attempt_count : null,
    terminal: terminal ? 1 : 0,
  };
}

// Pure: is this lineage entitled right now, and where is its grace anchored?
// past_due is entitled only inside the grace window opened by Stripe's latest
// UNPAID invoice; `unpaid` is never entitled (as before).
export function lineageEntitlement(lineage, nowMs = Date.now()) {
  if (!lineage || lineage.terminal) return { entitled: false, grace_anchor: null };
  const status = String(lineage.status || "");
  if (status === "active" || status === "trialing") {
    const periodOk = !lineage.current_period_end || Date.parse(lineage.current_period_end) > nowMs;
    return { entitled: periodOk, grace_anchor: null };
  }
  if (status === "past_due") {
    const anchor = lineageGraceAnchor(lineage);
    return { entitled: getPaymentGraceState({ subscription_status: "past_due", payment_failed_at: anchor }).active, grace_anchor: anchor };
  }
  return { entitled: false, grace_anchor: null };
}

// Pure: the lineage an account row reflects — the best ENTITLED one, in the
// entitlement resolver's own order (paid, then trial, then payment grace;
// within one, the highest plan, then most recently fetched), else the most
// recently fetched. Same order as resolveCanonicalSubscriptionRow, so the
// stored row and the read-time answer never disagree.
export function bestLineage(lineages, nowMs = Date.now()) {
  const list = (lineages || []).filter(Boolean);
  const recent = (a, b) => String(b.fetched_at || "").localeCompare(String(a.fetched_at || ""))
    || String(b.stripe_subscription_id).localeCompare(String(a.stripe_subscription_id));
  const rank = (l) => PLAN_RANK[normalizePlan(l.plan)] ?? 0;
  const source = (l) => (l.status === "active" ? 2 : l.status === "trialing" ? 1 : 0);
  const entitled = list.filter((l) => lineageEntitlement(l, nowMs).entitled)
    .sort((a, b) => source(b) - source(a) || rank(b) - rank(a) || recent(a, b));
  return entitled[0] || [...list].sort(recent)[0] || null;
}

async function readLineage(env, subscriptionId) {
  return env.cybermeters_db
    .prepare("SELECT * FROM stripe_subscription_lineages WHERE stripe_subscription_id = ? LIMIT 1")
    .bind(subscriptionId).first();
}

// Compare-and-swap on `version` (C-49 N01): the write lands only if nobody
// else wrote this lineage since `expectedVersion` was read. Returns the stored
// lineage, or null on a lost race (the caller re-reads Stripe and retries).
async function writeLineage(env, l, expectedVersion) {
  const now = nowIso();
  const values = [l.stripe_customer_id, l.status, l.plan, l.stripe_price_id, l.billing_interval,
    l.current_period_start, l.current_period_end, l.cancel_at_period_end, l.latest_invoice_id,
    l.latest_invoice_status, l.latest_invoice_created, l.latest_invoice_attempts];
  let result;
  if (expectedVersion == null) {
    result = await env.cybermeters_db
      .prepare(`INSERT INTO stripe_subscription_lineages
          (stripe_customer_id, status, plan, stripe_price_id, billing_interval, current_period_start,
           current_period_end, cancel_at_period_end, latest_invoice_id, latest_invoice_status,
           latest_invoice_created, latest_invoice_attempts,
           stripe_subscription_id, owner_user_id, workspace_id, terminal, version, fetched_at, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?)
        ON CONFLICT(stripe_subscription_id) DO NOTHING`)
      .bind(...values, l.stripe_subscription_id, l.owner_user_id, l.workspace_id, l.terminal, now, now, now)
      .run();
  } else {
    result = await env.cybermeters_db
      .prepare(`UPDATE stripe_subscription_lineages SET
          stripe_customer_id = ?,
          status = CASE WHEN terminal = 1 OR ? = 1 THEN 'canceled' ELSE ? END,
          plan = ?, stripe_price_id = ?, billing_interval = ?, current_period_start = ?,
          current_period_end = ?, cancel_at_period_end = ?, latest_invoice_id = ?, latest_invoice_status = ?,
          latest_invoice_created = ?, latest_invoice_attempts = ?,
          terminal = MAX(terminal, ?), version = version + 1, fetched_at = ?, updated_at = ?
        WHERE stripe_subscription_id = ? AND version = ?`)
      .bind(values[0], l.terminal, values[1], ...values.slice(2), l.terminal, now, now, l.stripe_subscription_id, expectedVersion)
      .run();
  }
  if (Number(result?.meta?.changes ?? 0) !== 1) return null;
  // Exactly what was stored (terminal is monotonic, so a stored terminal stays).
  return {
    ...l,
    status: l.terminal ? "canceled" : l.status,
    version: expectedVersion == null ? 1 : expectedVersion + 1,
    fetched_at: now,
    created_at: now,
    updated_at: now,
  };
}

// Fetch one subscription and store it. null when Stripe does not know it.
const LINEAGE_WRITE_ATTEMPTS = 4;

async function refreshLineage(env, subscriptionId, hint = {}) {
  // Read the stored version BEFORE asking Stripe: a write based on this read
  // can then only land if no newer read has landed meanwhile.
  for (let attempt = 0; attempt < LINEAGE_WRITE_ATTEMPTS; attempt++) {
    const previous = await readLineage(env, subscriptionId);
    const fetched = await fetchStripeSubscription(env, subscriptionId);
    if (!fetched) return null;
    const stored = await writeFetchedLineage(env, subscriptionId, fetched, previous, hint);
    if (stored) return stored;
  }
  // Still contended: let Stripe retry the event rather than guess.
  throw new Error("stripe_lineage_write_contended");
}

async function writeFetchedLineage(env, subscriptionId, fetched, previous, hint) {
  const marked = await hasCanceledSubscriptionMarker(env, subscriptionId);
  const lineage = lineageFromStripeSubscription(env, fetched, {
    previous: marked ? { ...(previous || {}), terminal: 1 } : previous, hint,
  });
  if (lineage.stripe_price_id && getPlanFromStripePriceId(env, lineage.stripe_price_id, fetched?.metadata?.plan) === null) {
    console.error("[stripe_unknown_price_fail_closed]", { stripe_subscription_id: subscriptionId, stripe_price_id: lineage.stripe_price_id });
    await createAuditEvent(env, {
      user_id: lineage.owner_user_id,
      workspace_id: lineage.workspace_id,
      event_type: "stripe_unknown_price_fail_closed",
      entity_type: "subscription",
      entity_id: subscriptionId,
      description: "Stripe subscription carried a price ID with no canonical plan mapping — plan left unchanged (fail closed)",
      metadata: { stripe_price_id: lineage.stripe_price_id, metadata_plan: fetched?.metadata?.plan || null },
    }).catch(() => {});
  }
  return writeLineage(env, lineage, previous ? previous.version : null);
}

/**
 * Re-read one subscription from Stripe, store it, and re-derive the account row
 * of its customer from that customer's lineages. Returns the account row id, or
 * null when nothing could be mapped (Stripe does not know the subscription, or
 * it grants nothing and no row exists yet). Throws on a Stripe fetch failure.
 */
export async function syncStripeSubscription(env, subscriptionId, { hint = {} } = {}) {
  if (!subscriptionId) return null;
  const lineage = await refreshLineage(env, subscriptionId, hint);
  if (!lineage) {
    await createAuditEvent(env, {
      user_id: hint.owner_user_id || null,
      event_type: "stripe_subscription_unknown",
      entity_type: "subscription",
      entity_id: subscriptionId,
      description: "Stripe does not know this subscription id — no billing state changed",
      metadata: { stripe_subscription_id: subscriptionId },
    }).catch(() => {});
    return null;
  }

  // The account row: the one holding this subscription, else this customer's,
  // else (first purchase) the account's row that has no Stripe customer yet.
  const rowId = await findSubscriptionRowId(env, {
    stripeSubscriptionId: lineage.stripe_subscription_id,
    stripeCustomerId: lineage.stripe_customer_id,
    ownerUserId: lineage.owner_user_id,
    workspaceId: lineage.workspace_id,
  });
  const row = rowId
    ? await env.cybermeters_db.prepare("SELECT id, stripe_subscription_id FROM subscriptions WHERE id = ?").bind(rowId).first()
    : null;

  // A row written before lineages existed reflects a subscription with no
  // lineage yet: read it too, so the comparison is over the customer's truth.
  let rowLineageUnknown = false;
  const rowSub = row?.stripe_subscription_id;
  if (rowSub && rowSub !== subscriptionId && !(await readLineage(env, rowSub))) {
    rowLineageUnknown = !(await refreshLineage(env, rowSub, {}));
  }

  // Derive the account row from the customer's lineages, then confirm none of
  // them changed while it was written; a concurrent webhook that wrote a newer
  // lineage meanwhile makes this derivation re-run, so the row is never left
  // reflecting an older read (C-49 N01).
  const readSiblings = async () => {
    const list = lineage.stripe_customer_id
      ? ((await env.cybermeters_db.prepare("SELECT * FROM stripe_subscription_lineages WHERE stripe_customer_id = ?")
          .bind(lineage.stripe_customer_id).all()).results || [])
      : [await readLineage(env, subscriptionId)].filter(Boolean);
    if (rowSub && rowSub !== subscriptionId && !list.some((l) => l.stripe_subscription_id === rowSub)) {
      const rowLineage = await readLineage(env, rowSub);
      if (rowLineage) list.push(rowLineage);
    }
    return list;
  };
  const versionsOf = (list) => list.map((l) => `${l.stripe_subscription_id}:${l.version}`).sort().join(",");

  let accountRowId = rowId;
  let siblings = await readSiblings();
  for (let attempt = 0; attempt < LINEAGE_WRITE_ATTEMPTS; attempt++) {
    const best = bestLineage(siblings) || lineage;
    const ent = lineageEntitlement(best);

    // Never create a row for a lineage that grants nothing, and never replace a
    // row's subscription Stripe could not confirm unless the new one is entitled.
    if (!accountRowId && !ent.entitled) return null;
    if (rowLineageUnknown && !ent.entitled) return accountRowId;
    // A new customer's subscription for a workspace another customer's row
    // already holds (the production table allows one row per workspace): no
    // second row. The lineage alone carries the entitlement at read time
    // (lineageCandidateRows), instead of a failing insert retried forever.
    if (!accountRowId && best.workspace_id) {
      const occupied = await env.cybermeters_db
        .prepare(`SELECT id FROM subscriptions WHERE workspace_id = ?
                    AND stripe_customer_id IS NOT NULL AND stripe_customer_id <> ? LIMIT 1`)
        .bind(best.workspace_id, best.stripe_customer_id || "")
        .first();
      if (occupied?.id) return null;
    }

    accountRowId = await upsertStripeSubscriptionState(env, {
      owner_user_id: best.owner_user_id,
      workspace_id: best.workspace_id,
      plan: best.plan,
      billing_interval: best.billing_interval,
      subscription_status: best.status,
      stripe_customer_id: best.stripe_customer_id,
      stripe_subscription_id: best.stripe_subscription_id,
      stripe_price_id: best.stripe_price_id,
      current_period_start: best.current_period_start,
      current_period_end: best.current_period_end,
      cancel_at_period_end: best.cancel_at_period_end,
    });
    if (accountRowId) {
      // Grace from Stripe's invoice, not from when an event happened to arrive.
      await env.cybermeters_db
        .prepare("UPDATE subscriptions SET payment_failed_at = ?, payment_retry_count = ? WHERE id = ?")
        .bind(ent.grace_anchor, ent.grace_anchor ? (best.latest_invoice_attempts ?? 1) : 0, accountRowId)
        .run();
    }
    const after = await readSiblings();
    if (versionsOf(after) === versionsOf(siblings)) return accountRowId;
    siblings = after;
  }
  throw new Error("stripe_account_row_contended");
}

export async function handleCheckoutSessionCompleted(env, session) {
  const metadata = session?.metadata || {};
  const ownerUserId = metadata.user_id || session?.client_reference_id || null;
  const workspaceId = metadata.workspace_id || null;
  const stripeCustomerId = getStripeObjectId(session?.customer);
  const stripeSubscriptionId = getStripeObjectId(session?.subscription);

  // A completed checkout can still have an unpaid asynchronous payment. Only
  // a settled subscription checkout may activate a plan; subscription events
  // own the lifecycle when payment is pending or the subscription id is absent.
  if (!stripeSubscriptionId || !["paid", "no_payment_required"].includes(session?.payment_status)) {
    return null;
  }
  if (await hasCanceledSubscriptionMarker(env, stripeSubscriptionId)) return null;

  if (!workspaceId) {
    console.warn("[stripe_webhook_workspace_unresolved] checkout.session.completed: workspace_id missing from session metadata", {
      stripe_session_id: session?.id || null,
      stripe_customer_id: stripeCustomerId,
      user_id: ownerUserId,
    });
  }

  // The session names the subscription and the account it was bought for;
  // the subscription's state is read from Stripe, never from the session.
  return syncStripeSubscription(env, stripeSubscriptionId, {
    hint: { owner_user_id: ownerUserId, workspace_id: workspaceId, stripe_customer_id: stripeCustomerId },
  });
}

export async function handleStripeSubscriptionUpsert(env, subscription) {
  // The payload only says WHICH subscription changed; its state is read from
  // Stripe (syncStripeSubscription), so a late or older event changes nothing.
  if (!subscription?.id) return null;
  const metadata = subscription?.metadata || {};
  return syncStripeSubscription(env, subscription.id, {
    hint: {
      owner_user_id: metadata.user_id || null,
      workspace_id: metadata.workspace_id || null,
      stripe_customer_id: getStripeObjectId(subscription?.customer),
    },
  });
}

export async function handleStripeSubscriptionDeleted(env, subscription) {
  // A deletion may arrive before either checkout or subscription.created. The
  // processed-events table has no retention sweep; a deterministic marker
  // prevents later deliveries for this subscription from granting access.
  if (subscription?.id) {
    await env.cybermeters_db
      .prepare(`INSERT INTO stripe_processed_events (id, event_type, status, processed_at)
                VALUES (?, 'subscription_canceled', 'completed', datetime('now'))
                ON CONFLICT(id) DO UPDATE SET
                  event_type = 'subscription_canceled', status = 'completed', processed_at = datetime('now')`)
      .bind(canceledSubscriptionMarkerId(subscription.id))
      .run();
  }
  // The deletion makes this lineage terminal; the account row is re-derived
  // from the customer's lineages, so another still-paid subscription of the
  // same customer keeps its entitlement (C-49 F11). No subscription id → no
  // lineage to change.
  if (!subscription?.id) return null;
  const metadata = subscription?.metadata || {};
  const rowId = await syncStripeSubscription(env, subscription.id, {
    hint: {
      owner_user_id: metadata.user_id || null,
      workspace_id: metadata.workspace_id || null,
      stripe_customer_id: getStripeObjectId(subscription?.customer),
    },
  });
  if (!rowId) return null;
  const accountRow = await env.cybermeters_db
    .prepare("SELECT subscription_status, current_period_end FROM subscriptions WHERE id = ? LIMIT 1")
    .bind(rowId).first();
  // Another lineage still carries the account: nothing was cancelled for the customer.
  if (accountRow?.subscription_status !== "canceled") return rowId;
  const deletedPeriodEnd = accountRow?.current_period_end ?? null;

  // Billing audit trail — non-fatal
  await writeSubscriptionEvent(env, rowId, "subscription.deleted", subscription);

  // Notify workspace owner of cancellation via email + in-app notification.
  try {
    const subRow = await env.cybermeters_db
      .prepare(
        `SELECT s.owner_user_id, s.workspace_id, u.email, u.name
         FROM subscriptions s
         JOIN users u ON u.id = s.owner_user_id
         WHERE s.id = ?
         LIMIT 1`
      )
      .bind(rowId)
      .first();

    if (subRow?.email) {
      const frontendOrigin = getEmailFrontendOrigin(env);
      const billingUrl = frontendOrigin ? `${frontendOrigin}/billing` : null;
      const customerName = subRow.name || "there";
      const nextStepText = billingUrl
        ? `please visit your billing page at ${billingUrl}.`
        : "please contact CyberMeters support.";
      const nextStepHtml = billingUrl
        ? `please visit your <a href="${escapeEmailHtml(billingUrl)}">billing page</a>.`
        : "please contact CyberMeters support.";
      await sendCustomerEmail(
        "Your CyberMeters subscription has been cancelled",
        `Hi ${customerName},\n\nYour CyberMeters subscription has been cancelled. Paid monitoring has now stopped; your existing scans, reports and evidence history remain available to view.\n\nIf you believe this is an error or would like to resubscribe, ${nextStepText}\n\nCyberMeters Team`,
        `<p>Hi ${escapeEmailHtml(customerName)},</p><p>Your CyberMeters subscription has been cancelled. Paid monitoring has now stopped; your existing scans, reports and evidence history remain available to view.</p><p>If you believe this is an error or would like to resubscribe, ${nextStepHtml}</p><p>CyberMeters Team</p>`,
        env,
        "ALERT_EMAIL_FROM",
        [subRow.email]
      );
    }

    if (subRow?.workspace_id) {
      await createNotificationEvent(env, subRow.workspace_id, {
        type:     "subscription_canceled",
        severity: "high",
        title:    "Subscription cancelled",
        message:  "Your subscription has been cancelled. Paid monitoring has stopped; your existing evidence remains viewable. Visit Billing to resubscribe.",
        metadata: { subscription_id: rowId },
        user_id:  subRow.owner_user_id ?? null,
      }).catch(() => {});

      await createAuditEvent(env, {
        workspace_id: subRow.workspace_id,
        user_id:      subRow.owner_user_id ?? null,
        event_type:   "subscription_canceled",
        entity_type:  "subscription",
        entity_id:    rowId,
        description:  "Stripe subscription cancelled — account reverted to free plan",
        metadata:     {
          stripe_subscription_id: subscription?.id ?? null,
          current_period_end:     deletedPeriodEnd,
        },
      }).catch(() => {});
    }
  } catch {
    // Notification failure must not affect subscription state update
  }

  return rowId;
}

// An invoice changes subscription state only through the subscription it
// names, re-read from Stripe: a one-off invoice (no subscription id) never
// touches a subscription (C-49 F15/F16), and which invoice is current, paid or
// open is Stripe's latest_invoice, not this event (F07–F09). The grace anchor
// is that invoice's creation time, so a retried event never restarts it (F10).
async function syncFromInvoice(env, invoice) {
  const stripeSubscriptionId = getStripeInvoiceSubscriptionId(invoice);
  if (!stripeSubscriptionId) return null;
  return syncStripeSubscription(env, stripeSubscriptionId, {
    hint: { stripe_customer_id: getStripeObjectId(invoice?.customer) },
  });
}

export async function handleStripeInvoicePaymentFailed(env, invoice) {
  return syncFromInvoice(env, invoice);
}

export async function handleStripeInvoicePaymentSucceeded(env, invoice) {
  return syncFromInvoice(env, invoice);
}

// writeSubscriptionEvent — writes a row to subscription_events for billing audit log.
// Non-fatal: errors are logged but do not throw. Webhook response must not fail
// due to event logging issues (Stripe would retry, causing duplicate subscription state).
export async function writeSubscriptionEvent(env, subscriptionRowId, eventType, payload) {
  if (!subscriptionRowId) return;
  try {
    const eventId = createId("sev");
    await env.cybermeters_db
      .prepare(
        `INSERT INTO subscription_events (id, subscription_id, event_type, payload_json, created_at)
         VALUES (?, ?, ?, ?, datetime('now'))`
      )
      .bind(eventId, subscriptionRowId, eventType, payload ? JSON.stringify(payload) : null)
      .run();
  } catch (e) {
    console.error(`[subscription_events] write failed [${eventType}]: ${e?.message ?? e}`);
  }
}
