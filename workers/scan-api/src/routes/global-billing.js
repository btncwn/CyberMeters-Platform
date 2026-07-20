// ── Global billing routes ──
// Public billing plans, the token-authenticated DMARC signed-upload ingest,
// account-level billing subscription view, the Stripe webhook (idempotent
// event processing) and account-level Stripe checkout/portal endpoints.
// Extracted near-verbatim from index.js (router split, Phase 2 PR #19).
// Receives the per-request routeCtx from index.js; returns a Response when a
// route matches, or null so the main router continues.
import { BILLING_PLAN_METADATA, getEffectivePlan, getUserPlan, normalizeBillingInterval, normalizePlan } from "../engines/entitlements.js";
import { extractIngestToken, hashIngestToken } from "../engines/rua-routing.js";
import { findSubscriptionRowId, getBillingIntervalFromStripeSubscription, getPlanFromStripePriceId, getStripeObjectId, getStripePriceIdForPlan, getStripeSubscriptionPrice, handleCheckoutSessionCompleted, handleStripeInvoicePaymentFailed, handleStripeInvoicePaymentSucceeded, handleStripeSubscriptionDeleted, handleStripeSubscriptionUpsert, normalizeStripeSubscriptionStatus, stripeUnixToIso, validateStripeBillingConfig, validateStripeSecretConfig, validateStripeWebhookConfig, verifyStripePriceMatchesPolicy, verifyStripeWebhookSignature, writeSubscriptionEvent } from "../engines/stripe.js";
import { auditApiTokenSessionRouteDenied, getPublicBillingPlans, parseCheckoutPlan } from "../engines/subscription-state.js";
import { ingestDmarcReport, ingestEndpointIsActive } from "../lib/dmarc-ingest.js";
import { createAuditEvent, createNotificationEvent } from "../lib/events.js";
import { sendLifecycleEmail } from "../lib/lifecycle-email.js";

export async function globalBillingRoutes(rctx) {
  const { request, env, url, json, serverError,
          requireAuth, consumeApiRateLimit, validateFrontendRedirectUrl } = rctx;

    // ── GET /api/billing/plans ──────────────────────────────────────────
    // Public billing metadata for future pricing/billing UI. Stripe price IDs
    // are intentionally not returned; checkout resolves prices server-side.
    if (request.method === "GET" && url.pathname === "/api/billing/plans") {
      const stripeConfig = validateStripeBillingConfig(env);
      return json({
        currency: "gbp",
        checkout_enabled: stripeConfig.ok,
        plans: getPublicBillingPlans(),
        stripe: {
          configured: stripeConfig.ok,
        },
      });
    }

    // ── POST /api/dmarc-ingest ──────────────────────────────────────────
    // Assisted DMARC Upload v1 — token-authenticated signed upload. No session
    // auth: identity is the per-workspace+domain upload token presented in an
    // Authorization: Bearer header (or X-CM-Ingest-Token fallback). The token
    // hash resolves to exactly one workspace+domain binding; ingestion may only
    // append DMARC report data. Body is raw XML (or JSON { xml }). The global
    // 1 MB request-body guard above caps payload size before this point.
    if (request.method === "POST" && url.pathname === "/api/dmarc-ingest") {
      try {
        const token = extractIngestToken(request);
        if (!token) {
          return json({ imported: false, error: "missing_token",
            message: "Missing upload credentials." }, 401);
        }
        const tokenHash = await hashIngestToken(token);
        const endpoint = await env.cybermeters_db
          .prepare(`SELECT * FROM dmarc_ingest_endpoints WHERE token_hash = ? LIMIT 1`)
          .bind(tokenHash).first();
        if (!ingestEndpointIsActive(endpoint)) {
          // Customer-safe: do not distinguish unknown vs revoked to the caller.
          await createAuditEvent(env, {
            workspace_id: endpoint?.workspace_id || null, user_id: null,
            event_type: "dmarc_ingest_rejected", entity_type: "domain",
            entity_id: endpoint?.domain_id || null,
            description: "Rejected DMARC signed upload with invalid or revoked key",
            metadata: { source: "signed_upload",
                        reason: endpoint ? "revoked_or_inactive" : "unknown_token",
                        ingest_endpoint_id: endpoint?.id || null },
          });
          return json({ imported: false, error: "invalid_token",
            message: "Upload credentials are invalid or have been revoked." }, 401);
        }

        // Abuse control: per-endpoint and per-workspace hourly caps. FAIL CLOSED —
        // DMARC ingest is an externally reachable write path (XML parse + D1/R2
        // persistence); if the rate-limit store is unavailable the cap must not
        // silently evaporate under the very D1 stress an abuse flood would create.
        // Returns 503 (retryable) BEFORE any parse/persistence, so no partial D1/R2
        // state is written; dedup is unaffected (it runs later inside ingest).
        const rl = await consumeApiRateLimit(env,
          [{ scope: "dmarc_ingest_endpoint", scope_id: endpoint.id },
           { scope: "dmarc_ingest_ws", scope_id: endpoint.workspace_id }],
          "dmarc_ingest", 120, 3600, { failClosed: true });
        if (rl) {
          const unavailable = rl.status === 503;
          console.warn("[dmarc-ingest] rate-limit gate", JSON.stringify({
            ingest_endpoint_id: endpoint.id, workspace_id: endpoint.workspace_id,
            reason: unavailable ? "rate_limit_unavailable" : "rate_limited",
          }));
          return json({ imported: false,
            error:   unavailable ? "rate_limit_unavailable" : "rate_limited",
            message: unavailable
              ? "Report ingestion is temporarily unavailable. Please retry shortly."
              : "Too many uploads. Please retry later." }, rl.status);
        }

        // Read body: raw XML by default, or JSON { xml } when so labelled.
        let xmlString = null;
        const ct = (request.headers.get("Content-Type") || "").toLowerCase();
        if (ct.includes("application/json")) {
          const body = await request.json().catch(() => null);
          xmlString = body && typeof body.xml === "string" ? body.xml : null;
        } else {
          xmlString = await request.text().catch(() => null);
        }
        if (!xmlString || !xmlString.trim()) {
          await createAuditEvent(env, {
            workspace_id: endpoint.workspace_id, user_id: null,
            event_type: "dmarc_ingest_rejected", entity_type: "domain", entity_id: endpoint.domain_id,
            description: `Rejected empty DMARC signed upload for ${endpoint.domain}`,
            metadata: { source: "signed_upload", reason: "empty_body", ingest_endpoint_id: endpoint.id },
          });
          return json({ imported: false, error: "missing_xml",
            message: "No report content was provided.", source: "signed_upload" }, 400);
        }

        const result = await ingestDmarcReport(env, {
          workspaceId: endpoint.workspace_id, domain: endpoint.domain, source: "signed_upload",
          xmlString, actorUserId: null, ingestEndpointId: endpoint.id, domainId: endpoint.domain_id,
          enforceDomainMatch: true,
        });

        // Record the authenticated use regardless of dedupe/parse outcome.
        await env.cybermeters_db
          .prepare(`UPDATE dmarc_ingest_endpoints SET last_used_at = datetime('now'), last_signed_upload_at = datetime('now') WHERE id = ?`)
          .bind(endpoint.id).run();

        if (!result.ok) {
          await createAuditEvent(env, {
            workspace_id: endpoint.workspace_id, user_id: null,
            event_type: "dmarc_ingest_rejected", entity_type: "domain", entity_id: endpoint.domain_id,
            description: `Rejected DMARC signed upload for ${endpoint.domain}: ${result.error}`,
            metadata: { source: "signed_upload", reason: result.error, ingest_endpoint_id: endpoint.id },
          });
          return json({ imported: false, error: result.error, message: result.message,
            source: "signed_upload" }, result.status || 422);
        }
        if (result.duplicate) {
          return json({ imported: false, duplicate: true,
            message: "This report was already imported and was not counted again.",
            source: "signed_upload" });
        }
        return json({ imported: true, duplicate: false,
          records: result.records, messages: result.messages, source: "signed_upload" });
      } catch (e) {
        return serverError("dmarc-ingest", e, "Report ingestion failed.");
      }
    }

    // ── GET /api/billing/subscription ───────────────────────────────────
    // Account-scoped subscription state used by the Billing page. Stripe is
    // not queried at request time; webhooks keep D1 as the platform source of
    // truth for plan, status, billing cycle, and renewal period.
    if (request.method === "GET" && url.pathname === "/api/billing/subscription") {
      const user = await requireAuth(request, env);
      if (!user) return json({ error: "Unauthorized" }, 401);
      try {
        const sub = await env.cybermeters_db
          .prepare(
            `SELECT plan,
                    subscription_status AS status,
                    billing_interval AS billing_cycle,
                    current_period_end
             FROM subscriptions
             WHERE owner_user_id = ?
             ORDER BY COALESCE(updated_at, created_at) DESC
             LIMIT 1`
          )
          .bind(user.id)
          .first();
        const plan = await getUserPlan(user.id, env);
        return json(sub ? {
          plan,
          status: sub.status || "active",
          billing_cycle: normalizeBillingInterval(sub.billing_cycle),
          current_period_end: sub.current_period_end ?? null,
        } : {
          plan,
          status: "active",
          billing_cycle: "monthly",
          current_period_end: null,
        });
      } catch (e) {
        return serverError("billing/subscription", e, "Unable to load subscription.");
      }
    }

    // ── POST /api/billing/webhook ─────────────────────────────────────────
    // Stripe webhook receiver. Verifies the Stripe-Signature header using
    // HMAC-SHA256, then synchronises subscription lifecycle events into D1.
    // No session auth — identity is established by the webhook signature.
    // Returns 5xx after a valid signature if D1 synchronization fails so
    // Stripe retries transient persistence failures.
    if (request.method === "POST" && (url.pathname === "/api/billing/webhook" || url.pathname === "/api/stripe/webhook")) {
      // Read raw body first — required before any other body consumption so
      // the exact bytes Stripe signed are available for HMAC verification.
      const rawBody = await request.text();

      const webhookConfig = validateStripeWebhookConfig(env);
      if (!webhookConfig.ok) {
        return json({
          error:   webhookConfig.error,
          missing: webhookConfig.missing,
          message: "Stripe webhook secret is not configured.",
        }, 503);
      }

      const sigHeader = request.headers.get("Stripe-Signature") || "";
      const sigResult = await verifyStripeWebhookSignature(rawBody, sigHeader, env.STRIPE_WEBHOOK_SECRET);
      if (!sigResult.ok) {
        return json({ error: sigResult.error }, 400);
      }

      let event;
      try { event = JSON.parse(rawBody); } catch {
        return json({ error: "invalid_json" }, 400);
      }

      const eventType = event?.type ?? "unknown";
      const obj       = event?.data?.object;

      // Environment guard (Q3): a test-mode event must never mutate live subscription
      // state (and vice-versa). Derive our configured mode from the secret key; when
      // determinable and it disagrees with event.livemode, acknowledge (200 — so Stripe
      // stops retrying) but DO NOT process. No marker is claimed and no state mutates.
      const keyMode = String(env.STRIPE_SECRET_KEY || "").includes("_test_") ? "test"
                    : String(env.STRIPE_SECRET_KEY || "").includes("_live_") ? "live" : null;
      if (keyMode && ((keyMode === "live") !== (event?.livemode === true))) {
        return json({ received: true, ignored: "environment_mismatch" }, 200);
      }

      // ── Idempotency STATE MACHINE (Q3) ────────────────────────────────────
      // The processed-event row is a CLAIM, not a completion marker. It is written as
      // 'processing' and only advanced to 'completed' AFTER all side effects succeed
      // (see the success/catch tails below). A duplicate of a 'completed' event is
      // skipped; a 'failed' event — or a 'processing' row whose claim has gone stale
      // (a crashed attempt, older than the lease) — is re-claimed so the Stripe retry
      // actually re-runs. This closes the drift where a marker committed before a
      // partial failure permanently suppressed retries. Signature is verified above.
      const eventId = event?.id;
      const CLAIM_LEASE_MS = 2 * 60 * 1000; // a live handler finishes well within 2 min
      if (eventId) {
        const claim = await env.cybermeters_db
          .prepare(`INSERT OR IGNORE INTO stripe_processed_events (id, event_type, status, processed_at) VALUES (?, ?, 'processing', datetime('now'))`)
          .bind(eventId, eventType)
          .run()
          .catch(() => null);
        const claimed = claim && (claim.meta?.changes ?? 0) === 1;
        if (!claimed) {
          const existing = await env.cybermeters_db
            .prepare(`SELECT status, processed_at FROM stripe_processed_events WHERE id = ? LIMIT 1`)
            .bind(eventId)
            .first()
            .catch(() => null);
          const status = existing?.status ?? "completed";
          if (status === "completed") {
            return json({ received: true, deduped: true }, 200);
          }
          // 'failed', or a 'processing' row past its lease (crashed attempt), may be
          // re-claimed. A fresh 'processing' row is a live concurrent delivery — leave
          // it to its owner and just acknowledge (no double-apply).
          const staleBefore = new Date(Date.now() - CLAIM_LEASE_MS)
            .toISOString().replace("T", " ").replace(/\.\d+Z$/, "");
          const reclaimable = status === "failed" ||
            (status === "processing" && String(existing?.processed_at ?? "") <= staleBefore);
          if (!reclaimable) {
            return json({ received: true, deduped: true }, 200);
          }
          // Optimistic CAS on the observed processed_at so two concurrent retries
          // cannot both win the re-claim.
          const recl = await env.cybermeters_db
            .prepare(`UPDATE stripe_processed_events SET status = 'processing', processed_at = datetime('now') WHERE id = ? AND status = ? AND processed_at = ?`)
            .bind(eventId, status, existing?.processed_at ?? null)
            .run()
            .catch(() => null);
          if (!recl || (recl.meta?.changes ?? 0) === 0) {
            return json({ received: true, deduped: true }, 200);
          }
        }
      }

      try {
        switch (eventType) {

          // ── checkout.session.completed ────────────────────────────────────
          // Customer completed Stripe-hosted checkout. Writes stripe_customer_id
          // and stripe_subscription_id into subscriptions. getEffectivePlan()
          // will return the new plan once subscription_status = 'active'.
          // current_period_end is absent on the session object — it arrives
          // seconds later via customer.subscription.created.
          case "checkout.session.completed": {
            const rowId = await handleCheckoutSessionCompleted(env, obj);
            const metadata = obj?.metadata || {};
            await createAuditEvent(env, {
              user_id:     metadata.user_id || obj?.client_reference_id || null,
              event_type:  "billing_checkout_completed",
              entity_type: "stripe_checkout_session",
              entity_id:   obj?.id || null,
              description: "Stripe checkout completed",
              metadata:    {
                subscription_row_id: rowId,
                stripe_session_id: obj?.id || null,
                stripe_customer_id: getStripeObjectId(obj?.customer),
                stripe_subscription_id: getStripeObjectId(obj?.subscription),
                plan: normalizePlan(metadata.plan),
                interval: normalizeBillingInterval(metadata.interval),
              },
            });
            await writeSubscriptionEvent(env, rowId, "checkout_completed", {
              stripe_session_id: obj?.id || null,
              plan: normalizePlan(metadata.plan),
              interval: normalizeBillingInterval(metadata.interval),
            });
            break;
          }

          // ── customer.subscription.created ─────────────────────────────────
          // Fires seconds after checkout.session.completed. Carries the exact
          // Stripe status and current_period_end. Upserts the subscriptions row
          // so getEffectivePlan() reads the correct plan and expiry.
          case "customer.subscription.created": {
            const rowId = await handleStripeSubscriptionUpsert(env, obj);
            const metadata = obj?.metadata || {};
            const price = getStripeSubscriptionPrice(obj, env);
            await createAuditEvent(env, {
              user_id:     metadata.user_id || null,
              event_type:  "subscription_created",
              entity_type: "subscription",
              entity_id:   obj?.id || rowId || null,
              description: "Stripe subscription created",
              metadata:    {
                subscription_row_id: rowId,
                stripe_subscription_id: obj?.id || null,
                stripe_customer_id: getStripeObjectId(obj?.customer),
                plan: getPlanFromStripePriceId(env, price?.id || null, metadata.plan),
                billing_interval: getBillingIntervalFromStripeSubscription(obj, metadata.interval),
                status: normalizeStripeSubscriptionStatus(obj?.status),
                current_period_end: stripeUnixToIso(obj?.current_period_end),
              },
            });
            await writeSubscriptionEvent(env, rowId, "subscription_created", {
              stripe_subscription_id: obj?.id || null,
              plan: getPlanFromStripePriceId(env, price?.id || null, metadata.plan),
              status: normalizeStripeSubscriptionStatus(obj?.status),
              current_period_start: stripeUnixToIso(obj?.current_period_start),
              current_period_end: stripeUnixToIso(obj?.current_period_end),
            });
            break;
          }

          // ── customer.subscription.updated ─────────────────────────────────
          // Plan change, renewal, payment status update, or cancel_at_period_end
          // flag set. Updates plan, billing_interval, subscription_status, and
          // current_period_end in subscriptions.
          case "customer.subscription.updated": {
            const metadata = obj?.metadata || {};
            let previousSubscription = null;
            try {
              const previousRowId = await findSubscriptionRowId(env, {
                ownerUserId: metadata.user_id || null,
                stripeSubscriptionId: obj?.id || null,
                stripeCustomerId: getStripeObjectId(obj?.customer),
              });
              previousSubscription = previousRowId
                ? await env.cybermeters_db
                  .prepare("SELECT plan, billing_interval, subscription_status FROM subscriptions WHERE id = ?")
                  .bind(previousRowId)
                  .first()
                : null;
            } catch { /* audit metadata lookup only */ }
            const rowId = await handleStripeSubscriptionUpsert(env, obj);
            const price = getStripeSubscriptionPrice(obj, env);
            const newPlan = getPlanFromStripePriceId(env, price?.id || null, metadata.plan);
            const previousPlan = previousSubscription?.plan ? normalizePlan(previousSubscription.plan) : null;
            await createAuditEvent(env, {
              user_id:     metadata.user_id || null,
              event_type:  "subscription_updated",
              entity_type: "subscription",
              entity_id:   obj?.id || rowId || null,
              description: "Stripe subscription updated",
              metadata:    {
                subscription_row_id: rowId,
                stripe_subscription_id: obj?.id || null,
                stripe_customer_id: getStripeObjectId(obj?.customer),
                previous_plan: previousPlan,
                plan: newPlan,
                plan_changed: previousPlan ? previousPlan !== newPlan : false,
                billing_interval: getBillingIntervalFromStripeSubscription(obj, metadata.interval),
                previous_billing_interval: previousSubscription?.billing_interval ?? null,
                status: normalizeStripeSubscriptionStatus(obj?.status),
                previous_status: previousSubscription?.subscription_status ?? null,
                current_period_end: stripeUnixToIso(obj?.current_period_end),
              },
            });
            await writeSubscriptionEvent(env, rowId, "subscription_updated", {
              stripe_subscription_id: obj?.id || null,
              plan: newPlan,
              plan_changed: previousPlan ? previousPlan !== newPlan : false,
              status: normalizeStripeSubscriptionStatus(obj?.status),
              cancel_at_period_end: obj?.cancel_at_period_end ?? null,
              current_period_start: stripeUnixToIso(obj?.current_period_start),
              current_period_end: stripeUnixToIso(obj?.current_period_end),
            });
            break;
          }

          // ── customer.subscription.deleted ─────────────────────────────────
          // Subscription has ended. Sets subscription_status = 'canceled'.
          // getEffectivePlan() returns 'free' for any non-active status.
          // Row is never deleted — historical record is preserved.
          case "customer.subscription.deleted": {
            const rowId = await handleStripeSubscriptionDeleted(env, obj);
            const metadata = obj?.metadata || {};
            await createAuditEvent(env, {
              user_id:     metadata.user_id || null,
              event_type:  "subscription_canceled",
              entity_type: "subscription",
              entity_id:   obj?.id || rowId || null,
              description: "Stripe subscription canceled",
              metadata:    {
                subscription_row_id: rowId,
                stripe_subscription_id: obj?.id || null,
                stripe_customer_id: getStripeObjectId(obj?.customer),
                status: "canceled",
                current_period_end: stripeUnixToIso(obj?.current_period_end),
              },
            });
            await writeSubscriptionEvent(env, rowId, "subscription_canceled", {
              stripe_subscription_id: obj?.id || null,
              status: "canceled",
              current_period_end: stripeUnixToIso(obj?.current_period_end),
            });
            break;
          }

          // ── invoice.payment_failed ───────────────────────────────────────
          // Payment failure should immediately remove paid entitlements from
          // runtime plan resolution. The row is retained and marked past_due;
          // later customer.subscription.updated events can restore active
          // status after Stripe collects payment.
          case "invoice.payment_failed": {
            const rowId = await handleStripeInvoicePaymentFailed(env, obj);
            await createAuditEvent(env, {
              user_id:     null,
              event_type:  "subscription_payment_failed",
              entity_type: "stripe_invoice",
              entity_id:   obj?.id || rowId || null,
              description: "Stripe invoice payment failed",
              metadata:    {
                subscription_row_id: rowId,
                stripe_invoice_id: obj?.id || null,
                stripe_subscription_id: getStripeObjectId(obj?.subscription),
                stripe_customer_id: getStripeObjectId(obj?.customer),
                attempt_count: obj?.attempt_count ?? null,
              },
            });
            await writeSubscriptionEvent(env, rowId, "payment_failed", {
              stripe_invoice_id: obj?.id || null,
              stripe_subscription_id: getStripeObjectId(obj?.subscription),
              attempt_count: obj?.attempt_count ?? null,
            });

            // Customer trust: a payment failure must never be silent. Email the
            // subscription owner (deduped once per invoice, so Stripe's retry
            // events don't spam) and mirror it in-app. Failures here must not
            // fail the webhook — Stripe would retry the whole event.
            if (rowId) {
              try {
                const subOwner = await env.cybermeters_db
                  .prepare("SELECT owner_user_id, workspace_id FROM subscriptions WHERE id = ? LIMIT 1")
                  .bind(rowId)
                  .first();
                if (subOwner?.owner_user_id) {
                  await sendLifecycleEmail(env, {
                    type: "lifecycle_payment_failed",
                    user_id: subOwner.owner_user_id,
                    workspace_id: subOwner.workspace_id ?? null,
                    ref: obj?.id || null,
                  }).catch(() => {});
                }
                if (subOwner?.workspace_id) {
                  await createNotificationEvent(env, subOwner.workspace_id, {
                    type:     "subscription_payment_failed",
                    severity: "high",
                    title:    "Payment failed",
                    message:  "Your latest subscription payment could not be processed. Update your payment method in Billing to keep your paid plan active.",
                    metadata: { subscription_id: rowId },
                    user_id:  subOwner.owner_user_id ?? null,
                  }).catch(() => {});
                }
              } catch {
                // Notification failure must not affect webhook processing
              }
            }
            break;
          }

          // ── invoice.payment_succeeded ────────────────────────────────────
          // Payment succeeded — clears past_due status and resets retry count.
          // Note: customer.subscription.updated also fires on renewal and is
          // the authoritative source for current_period_end. This handler only
          // clears the payment failure state.
          case "invoice.payment_succeeded": {
            const rowId = await handleStripeInvoicePaymentSucceeded(env, obj);
            await createAuditEvent(env, {
              user_id:     null,
              event_type:  "subscription_payment_succeeded",
              entity_type: "stripe_invoice",
              entity_id:   obj?.id || rowId || null,
              description: "Stripe invoice payment succeeded",
              metadata:    {
                subscription_row_id: rowId,
                stripe_invoice_id: obj?.id || null,
                stripe_subscription_id: getStripeObjectId(obj?.subscription),
                stripe_customer_id: getStripeObjectId(obj?.customer),
                amount_paid: obj?.amount_paid ?? null,
                currency: obj?.currency ?? null,
              },
            });
            await writeSubscriptionEvent(env, rowId, "payment_succeeded", {
              stripe_invoice_id: obj?.id || null,
              stripe_subscription_id: getStripeObjectId(obj?.subscription),
              amount_paid: obj?.amount_paid ?? null,
              currency: obj?.currency ?? null,
            });
            break;
          }

          // All other Stripe events are acknowledged and silently ignored.
          default:
            break;
        }
      } catch (e) {
        // Side effects failed — mark the claim 'failed' so the next Stripe retry
        // re-claims and RE-RUNS them (the marker never suppresses a retry after a
        // partial failure). Return 500 so Stripe retries (exp. backoff, ~25 attempts
        // over 72 h).
        console.error(`[webhook] handler error [${eventType}]: ${e?.message ?? e}`);
        if (eventId) {
          await env.cybermeters_db
            .prepare(`UPDATE stripe_processed_events SET status = 'failed', processed_at = datetime('now') WHERE id = ?`)
            .bind(eventId).run().catch(() => {});
        }
        return json({
          error:      "webhook_sync_failed",
          event_type: eventType,
          message:    "D1 synchronization failed. Stripe will retry.",
        }, 500);
      }

      // All side effects succeeded — NOW mark the event completed. Only after this
      // point does a duplicate delivery get safely skipped.
      if (eventId) {
        await env.cybermeters_db
          .prepare(`UPDATE stripe_processed_events SET status = 'completed', processed_at = datetime('now') WHERE id = ?`)
          .bind(eventId).run().catch(() => {});
      }
      return json({ received: true, event_type: eventType }, 200);
    }

    // ── POST /api/billing/checkout ──────────────────────────────────────
    // Stripe Checkout Flow v1. Creates a Stripe-hosted Checkout Session via
    // fetch. D1 subscription activation is intentionally deferred to webhooks.
    if (request.method === "POST" && url.pathname === "/api/billing/checkout") {
      const user = await requireAuth(request, env);
      if (!user) return json({ error: "Unauthorized" }, 401);
      // Checkout is an account-control browser flow, not an automation API.
      if (user.api_token_id) {
        await auditApiTokenSessionRouteDenied(env, user, request);
        return json({ error: "Session authentication required" }, 403);
      }

      let body;
      try { body = await request.json(); } catch { return json({ error: "Invalid JSON body" }, 400); }

      const parsedPlan = parseCheckoutPlan(body.plan);
      if (!parsedPlan.ok) {
        return json({
          error: "invalid_plan",
          message: "plan must be one of: starter, professional, business.",
        }, 400);
      }

      const requestedPlan = parsedPlan.plan;
      const interval = normalizeBillingInterval(body.interval);
      const metadata = BILLING_PLAN_METADATA[requestedPlan];

      if (!metadata?.checkout_enabled) {
        return json({
          error: "plan_not_checkout_eligible",
          plan: requestedPlan,
          message: "This plan is not available through self-service checkout.",
        }, 400);
      }

      const priceResolution = getStripePriceIdForPlan(env, requestedPlan, interval);
      if (!priceResolution.ok) {
        return json({
          error: priceResolution.error,
          ...(priceResolution.missing?.length ? { missing: priceResolution.missing } : {}),
          message: "Stripe billing configuration is not ready for checkout.",
        }, 503);
      }

      // Lockstep guard: the configured Stripe price must charge exactly what the
      // canonical pricing policy states for this plan/interval. A stale or wrong
      // price refuses checkout rather than charging a number the cards never showed.
      const priceCheck = await verifyStripePriceMatchesPolicy(env, requestedPlan, interval, priceResolution.price_id);
      if (!priceCheck.ok) {
        return json({
          error: priceCheck.error,
          message: "Checkout is temporarily unavailable while billing configuration is verified.",
        }, 503);
      }

      let subscription = null;
      try {
        subscription = await env.cybermeters_db
          .prepare(
            `SELECT id, stripe_customer_id, stripe_subscription_id, stripe_price_id,
                    billing_interval, cancel_at_period_end, current_period_end
             FROM subscriptions
             WHERE owner_user_id = ?`
          )
          .bind(user.id)
          .first();
      } catch (e) {
        return serverError("billing/checkout-subscription", e, "Unable to load billing information.");
      }

      // Validate redirect URLs
      const successUrl = validateFrontendRedirectUrl(body.success_url, env);
      const cancelUrl  = validateFrontendRedirectUrl(body.cancel_url, env);
      if (!successUrl) {
        return json({ error: "invalid_success_url", message: "success_url must use the configured CyberMeters frontend origin." }, 400);
      }
      if (!cancelUrl) {
        return json({ error: "invalid_cancel_url", message: "cancel_url must use the configured CyberMeters frontend origin." }, 400);
      }

      // Build Stripe Checkout Session params (Stripe accepts x-www-form-urlencoded only)
      const params = new URLSearchParams();
      params.set("mode",                    "subscription");
      params.set("line_items[0][price]",    priceResolution.price_id);
      params.set("line_items[0][quantity]", "1");
      params.set("success_url",             successUrl);
      params.set("cancel_url",              cancelUrl);
      params.set("metadata[user_id]",       String(user.id));
      params.set("metadata[plan]",          requestedPlan);
      params.set("metadata[interval]",      interval);
      params.set("subscription_data[metadata][user_id]",  String(user.id));
      params.set("subscription_data[metadata][plan]",     requestedPlan);
      params.set("subscription_data[metadata][interval]", interval);
      params.set("allow_promotion_codes", "true");

      // Prefer an existing Stripe customer record; fall back to customer_email
      // so Stripe auto-creates a Customer on checkout completion.
      if (subscription?.stripe_customer_id) {
        params.set("customer", subscription.stripe_customer_id);
      } else {
        params.set("customer_email", user.email);
      }

      // Call Stripe Checkout Sessions API via fetch (no SDK — Cloudflare Workers compatible)
      let stripeSession;
      try {
        const stripeRes = await fetch("https://api.stripe.com/v1/checkout/sessions", {
          method:  "POST",
          headers: {
            "Authorization": `Bearer ${env.STRIPE_SECRET_KEY}`,
            "Content-Type":  "application/x-www-form-urlencoded",
          },
          body: params.toString(),
        });

        const stripeData = await stripeRes.json();

        if (!stripeRes.ok) {
          console.error("[billing/checkout] Stripe API error", {
            status: stripeRes.status,
            type: stripeData?.error?.type ?? null,
            code: stripeData?.error?.code ?? null,
          });
          return json({
            error:             "stripe_api_error",
            message:           "Stripe Checkout Session creation failed. Please try again.",
          }, 502);
        }

        stripeSession = stripeData;
      } catch (e) {
        console.error(`[billing/checkout] ${e?.message ?? e}`);
        return json({
          error:   "stripe_request_failed",
          message: "Could not reach Stripe. Please try again.",
        }, 502);
      }

      // D1 is intentionally NOT updated here.
      // Plan activation and subscriptions sync happen in the webhook handler
      // when Stripe fires checkout.session.completed.
      await createAuditEvent(env, {
        user_id:     user.id,
        event_type:  "billing_checkout_session_created",
        entity_type: "stripe_checkout_session",
        entity_id:   stripeSession.id,
        description: `Stripe checkout session created for ${requestedPlan} (${interval})`,
        metadata:    { plan: requestedPlan, interval, stripe_session_id: stripeSession.id },
      });
      return json({
        checkout_url: stripeSession.url,
        session_id:   stripeSession.id,
      }, 200);
    }

    // ── POST /api/billing/portal ────────────────────────────────────────
    // Creates a Stripe-hosted Billing Portal Session for the authenticated
    // user's existing Stripe customer. This is read-only for D1; Stripe
    // lifecycle changes still flow back through webhooks.
    if (request.method === "POST" && url.pathname === "/api/billing/portal") {
      const user = await requireAuth(request, env);
      if (!user) return json({ error: "Unauthorized" }, 401);
      // Billing portal grants account-level Stripe access; require a user session.
      if (user.api_token_id) {
        await auditApiTokenSessionRouteDenied(env, user, request);
        return json({ error: "Session authentication required" }, 403);
      }

      let body;
      try { body = await request.json(); } catch { return json({ error: "Invalid JSON body" }, 400); }

      const returnUrl = validateFrontendRedirectUrl(body.return_url, env);
      if (!returnUrl) {
        return json({
          error: "invalid_return_url",
          message: "return_url must use the configured CyberMeters frontend origin.",
        }, 400);
      }

      const stripeConfig = validateStripeSecretConfig(env);
      if (!stripeConfig.ok) {
        return json({
          error: stripeConfig.error,
          missing: stripeConfig.missing,
          message: "Stripe billing configuration is not ready for Customer Portal.",
        }, 503);
      }

      let subscription = null;
      try {
        subscription = await env.cybermeters_db
          .prepare(
            `SELECT id, stripe_customer_id
             FROM subscriptions
             WHERE owner_user_id = ?
             ORDER BY COALESCE(updated_at, created_at) DESC
             LIMIT 1`
          )
          .bind(user.id)
          .first();
      } catch (e) {
        return serverError("billing/portal-subscription", e, "Unable to load billing information.");
      }

      if (!subscription) {
        return json({ error: "subscription_not_found" }, 404);
      }
      if (!subscription.stripe_customer_id) {
        return json({ error: "stripe_customer_missing" }, 409);
      }

      const params = new URLSearchParams();
      params.set("customer", subscription.stripe_customer_id);
      params.set("return_url", returnUrl);

      let portalSession;
      try {
        const stripeRes = await fetch("https://api.stripe.com/v1/billing_portal/sessions", {
          method: "POST",
          headers: {
            "Authorization": `Bearer ${env.STRIPE_SECRET_KEY}`,
            "Content-Type":  "application/x-www-form-urlencoded",
          },
          body: params.toString(),
        });

        const stripeData = await stripeRes.json();
        if (!stripeRes.ok) {
          console.error("[billing/portal] Stripe API error", {
            status: stripeRes.status,
            type: stripeData?.error?.type ?? null,
            code: stripeData?.error?.code ?? null,
          });
          return json({
            error:             "stripe_api_error",
            message:           "Stripe Billing Portal Session creation failed. Please try again.",
          }, 502);
        }

        portalSession = stripeData;
      } catch (e) {
        console.error(`[billing/portal] ${e?.message ?? e}`);
        return json({
          error:   "stripe_request_failed",
          message: "Could not reach Stripe. Please try again.",
        }, 502);
      }

      await createAuditEvent(env, {
        user_id:     user.id,
        event_type:  "billing_portal_opened",
        entity_type: "stripe_billing_portal_session",
        entity_id:   portalSession.id,
        description: "Stripe billing portal session created",
        metadata:    { subscription_id: subscription.id, stripe_session_id: portalSession.id },
      });
      return json({
        portal_url: portalSession.url,
        session_id:  portalSession.id,
      }, 200);
	    }
	

  return null;
}
