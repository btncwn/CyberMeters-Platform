// ── Stripe billing integration ──
// Stripe price-map + config validation, webhook signature verification (HMAC-SHA256),
// subscription/invoice object parsing, subscription-state upsert, and the checkout/subscription/
// invoice webhook event handlers + billing audit-event writer. Extracted verbatim from index.js
// (monolith decomposition, Phase 1c). Price-map/signature-parsing/crypto helpers +
// upsertStripeSubscriptionState are module-internal.
import { createAuditEvent, createNotificationEvent } from "../lib/events.js";
import { createId } from "../lib/util.js";
import { escapeEmailHtml, getEmailFrontendOrigin, sendCustomerEmail } from "../lib/lifecycle-email.js";
import { getPaymentGraceState, normalizeBillingInterval, normalizePlan } from "./entitlements.js";
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

export async function findSubscriptionRowId(env, { ownerUserId = null, stripeSubscriptionId = null, stripeCustomerId = null } = {}) {
  if (ownerUserId) {
    const row = await env.cybermeters_db
      .prepare("SELECT id FROM subscriptions WHERE owner_user_id = ? LIMIT 1")
      .bind(ownerUserId)
      .first();
    if (row?.id) return row.id;
  }

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

  return null;
}

async function upsertStripeSubscriptionState(env, state) {
  const ownerUserId = state.owner_user_id || null;
  const workspaceId = state.workspace_id || null;
  const stripeCustomerId = state.stripe_customer_id || null;
  const stripeSubscriptionId = state.stripe_subscription_id || null;
  const rowId = await findSubscriptionRowId(env, {
    ownerUserId,
    stripeSubscriptionId,
    stripeCustomerId,
  });

  if (rowId) {
    const cancelAtPeriodEnd = state.cancel_at_period_end != null
      ? (state.cancel_at_period_end ? 1 : 0)
      : null;
    // Stale-event guard (Q3, item 13): Stripe can deliver subscription events out of
    // order. current_period_end only ever advances on renewal, so never let an
    // incoming (possibly stale) event move it BACKWARD — that would shorten a
    // customer's entitlement window from an old delivery. Both stored and incoming
    // values are same-format ISO timestamps, so lexical >= is chronological. Other
    // fields still apply (a cancel that does not advance the period must take effect);
    // full status-transition ordering is not enforced (the schema carries no per-event
    // sequence — documented residual).
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
             current_period_end = CASE
               WHEN ? IS NOT NULL AND (current_period_end IS NULL OR ? >= current_period_end) THEN ?
               ELSE current_period_end END,
             cancel_at_period_end = COALESCE(?, cancel_at_period_end),
             workspace_id = COALESCE(?, workspace_id),
             updated_at = datetime('now')
         WHERE id = ?`
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
        cpEnd, cpEnd, cpEnd,
        cancelAtPeriodEnd,
        workspaceId,
        rowId
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
           WHERE id = ?`
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
          trialRow.id
        )
        .run();
      return trialRow.id;
    }
  }

  const id = createId("sub");
  const cancelAtPeriodEndInsert = state.cancel_at_period_end != null
    ? (state.cancel_at_period_end ? 1 : 0)
    : 0;
  await env.cybermeters_db
    .prepare(
      `INSERT INTO subscriptions
         (id, owner_user_id, workspace_id, plan, billing_interval, subscription_status, status,
          stripe_customer_id, stripe_subscription_id, stripe_price_id,
          current_period_start, current_period_end, cancel_at_period_end,
          created_at, updated_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'), datetime('now'))`
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
      cancelAtPeriodEndInsert
    )
    .run();
  return id;
}

export async function handleCheckoutSessionCompleted(env, session) {
  const metadata = session?.metadata || {};
  const ownerUserId = metadata.user_id || session?.client_reference_id || null;
  const workspaceId = metadata.workspace_id || null;
  const plan = normalizePlan(metadata.plan);
  const billingInterval = normalizeBillingInterval(metadata.interval);
  const stripeCustomerId = getStripeObjectId(session?.customer);
  const stripeSubscriptionId = getStripeObjectId(session?.subscription);

  if (!workspaceId) {
    console.warn("[stripe_webhook_workspace_unresolved] checkout.session.completed: workspace_id missing from session metadata", {
      stripe_session_id: session?.id || null,
      stripe_customer_id: stripeCustomerId,
      user_id: ownerUserId,
    });
  }

  return upsertStripeSubscriptionState(env, {
    owner_user_id: ownerUserId,
    workspace_id: workspaceId,
    plan,
    billing_interval: billingInterval,
    subscription_status: "active",
    stripe_customer_id: stripeCustomerId,
    stripe_subscription_id: stripeSubscriptionId,
  });
}

export async function handleStripeSubscriptionUpsert(env, subscription) {
  const metadata = subscription?.metadata || {};
  const price = getStripeSubscriptionPrice(subscription, env);
  const priceId = price?.id || null;
  // Price-authoritative mapping. metadata.plan applies only when the event
  // carries no price at all; a present-but-unknown price yields null and the
  // upsert keeps the stored plan unchanged (fail-closed — see below).
  const plan = getPlanFromStripePriceId(env, priceId, metadata.plan);
  if (priceId && plan === null) {
    console.error("[stripe_unknown_price_fail_closed]", {
      stripe_subscription_id: subscription?.id || null,
      stripe_price_id: priceId,
      metadata_plan: metadata.plan || null,
    });
    await createAuditEvent(env, {
      user_id: metadata.user_id || null,
      workspace_id: metadata.workspace_id || null,
      event_type: "stripe_unknown_price_fail_closed",
      entity_type: "subscription",
      entity_id: subscription?.id || null,
      description: "Stripe subscription event carried a price ID with no canonical plan mapping — plan left unchanged (fail closed)",
      metadata: { stripe_price_id: priceId, metadata_plan: metadata.plan || null },
    }).catch(() => {});
  }
  const billingInterval = getBillingIntervalFromStripeSubscription(subscription, metadata.interval);

  // Resolve workspace_id — order of precedence:
  //   1. subscription.metadata.workspace_id (set by checkout via subscription_data.metadata)
  //   2. existing subscriptions row (lookup by stripe_subscription_id → stripe_customer_id)
  // Never pass null workspace_id into an INSERT — the production table has workspace_id NOT NULL.
  let workspaceId = metadata.workspace_id || null;
  if (!workspaceId) {
    const stripeSubId = subscription?.id || null;
    const stripeCustomerId = getStripeObjectId(subscription?.customer);
    try {
      let existingRow = null;
      if (stripeSubId) {
        existingRow = await env.cybermeters_db
          .prepare("SELECT workspace_id FROM subscriptions WHERE stripe_subscription_id = ? LIMIT 1")
          .bind(stripeSubId)
          .first();
      }
      if (!existingRow?.workspace_id && stripeCustomerId) {
        existingRow = await env.cybermeters_db
          .prepare("SELECT workspace_id FROM subscriptions WHERE stripe_customer_id = ? LIMIT 1")
          .bind(stripeCustomerId)
          .first();
      }
      workspaceId = existingRow?.workspace_id || null;
    } catch { /* resolution best-effort; upsert will guard below */ }
    if (!workspaceId) {
      console.warn("[stripe_webhook_workspace_unresolved] workspace_id not in subscription metadata and no existing row found", {
        stripe_subscription_id: subscription?.id || null,
        stripe_customer_id: getStripeObjectId(subscription?.customer),
        user_id: metadata.user_id || null,
      });
    }
  }

  // Period boundary: top-level on older API versions, base item on Basil+.
  const period = getStripeSubscriptionPeriod(subscription, env);

  return upsertStripeSubscriptionState(env, {
    owner_user_id: metadata.user_id || null,
    workspace_id: workspaceId,
    plan,
    billing_interval: billingInterval,
    subscription_status: normalizeStripeSubscriptionStatus(subscription?.status),
    stripe_customer_id: getStripeObjectId(subscription?.customer),
    stripe_subscription_id: subscription?.id || null,
    stripe_price_id: priceId,
    current_period_start: period.start,
    current_period_end: period.end,
    cancel_at_period_end: subscription?.cancel_at_period_end ?? null,
  });
}

export async function handleStripeSubscriptionDeleted(env, subscription) {
  const metadata = subscription?.metadata || {};
  const rowId = await findSubscriptionRowId(env, {
    ownerUserId: metadata.user_id || null,
    stripeSubscriptionId: subscription?.id || null,
    stripeCustomerId: getStripeObjectId(subscription?.customer),
  });

  if (!rowId) return null;
  // Legacy `status` written in lockstep with subscription_status (see
  // upsertStripeSubscriptionState); period end read Basil-aware.
  const deletedPeriodEnd = getStripeSubscriptionPeriod(subscription, env).end;
  await env.cybermeters_db
    .prepare(
      `UPDATE subscriptions
       SET subscription_status = 'canceled',
           status = 'canceled',
           current_period_end = COALESCE(?, current_period_end),
           updated_at = datetime('now')
       WHERE id = ?`
    )
    .bind(deletedPeriodEnd, rowId)
    .run();

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

export async function handleStripeInvoicePaymentFailed(env, invoice) {
  const stripeSubscriptionId = getStripeObjectId(invoice?.subscription);
  const stripeCustomerId = getStripeObjectId(invoice?.customer);
  const rowId = await findSubscriptionRowId(env, {
    stripeSubscriptionId,
    stripeCustomerId,
  });

  if (!rowId) return null;
  await env.cybermeters_db
    .prepare(
      `UPDATE subscriptions
       SET subscription_status = 'past_due',
           status = 'past_due',
           payment_failed_at = datetime('now'),
           payment_retry_count = COALESCE(payment_retry_count, 0) + 1,
           updated_at = datetime('now')
       WHERE id = ?`
    )
    .bind(rowId)
    .run();
  return rowId;
}

export async function handleStripeInvoicePaymentSucceeded(env, invoice) {
  const stripeSubscriptionId = getStripeObjectId(invoice?.subscription);
  const stripeCustomerId = getStripeObjectId(invoice?.customer);
  const rowId = await findSubscriptionRowId(env, {
    stripeSubscriptionId,
    stripeCustomerId,
  });

  if (!rowId) return null;
  // Clear past_due state when payment succeeds; only restore active if currently past_due
  // (subscription.updated events also fire on renewal and update period_end authoritatively).
  // Both SET expressions read the OLD subscription_status, so `status` lands in
  // lockstep with the new subscription_status — and a historically stale
  // `status` value is re-synced by the same write.
  await env.cybermeters_db
    .prepare(
      `UPDATE subscriptions
       SET subscription_status = CASE WHEN subscription_status = 'past_due' THEN 'active' ELSE subscription_status END,
           status = CASE WHEN subscription_status = 'past_due' THEN 'active' ELSE subscription_status END,
           payment_failed_at = NULL,
           payment_retry_count = 0,
           updated_at = datetime('now')
       WHERE id = ?`
    )
    .bind(rowId)
    .run();
  return rowId;
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
