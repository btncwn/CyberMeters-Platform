// ── Billing + free-scan routes ──
// Public free-scan (rate-limited, bounded six-module snapshot), workspace
// subscription state, public plans list and workspace Stripe checkout/portal
// endpoints. Extracted near-verbatim from index.js (router split, Phase 2
// PR #13). Receives the per-request routeCtx from index.js; returns a
// Response when a route matches, or null so the main router continues.
import { runDnsModule } from "../engines/dns-scan.js";
import { runEmailModule } from "../engines/email-scan.js";
import { runHeadersModule } from "../engines/headers-scan.js";
import { runSslModule } from "../engines/ssl-scan.js";
import { runSubdomainsModule } from "../engines/subdomains-scan.js";
import { runTechModule } from "../engines/tech-scan.js";
import {
  buildFreeScanEvidence,
} from "../engines/free-scan-evidence.js";
import {
  buildFreeScanPreview,
  FREE_SCAN_DEADLINE_MS,
  FREE_SCAN_SUBREQUEST_LIMIT,
} from "../engines/free-scan-preview.js";
import { createCertificateTransparencyCache } from "../engines/ct-provider-cache.js";
import { makeDnsCache, PhysicalSubrequestCounter } from "../engines/scan-budget.js";
import { BILLING_PLAN_METADATA, getEffectiveDomainLimit, getPaymentGraceState, getPlanFeatures, normalizeBillingInterval, normalizePlan } from "../engines/entitlements.js";
import { getPlanLimits, getWorkspaceBillingUserId } from "../engines/plan-usage.js";
import { applyCheckoutConsentParams, getStripePriceIdForPlan, shouldRoutePlanChangeToPortal, validateStripeSecretConfig, verifyStripePriceMatchesPolicy } from "../engines/stripe.js";
import { TRIAL_PLAN, auditApiTokenSessionRouteDenied, getPublicBillingPlans, getTrialRemainingDays, getWorkspaceSubscription, isSubscriptionActive, isTrialActive, parseCheckoutPlan } from "../engines/subscription-state.js";
import { dnsQuery } from "../engines/dns.js";
import { createAuditEvent } from "../lib/events.js";
import { resolvesToPrivateIp } from "../lib/ssrf.js";
import { createId, isValidDomain } from "../lib/util.js";

export async function billingRoutes(rctx) {
  const { request, env, url, json, serverError,
          requireAuth, requireWorkspaceRole, consumeApiRateLimit, rateLimitScopeId } = rctx;
  const freeScanModuleRunners = {
    dns: runDnsModule,
    ssl: runSslModule,
    headers: runHeadersModule,
    email_security: runEmailModule,
    subdomains: runSubdomainsModule,
    technology_detection: runTechModule,
    ...(rctx.freeScanModuleRunners || {}),
  };
  const freeScanDnsQuery = rctx.freeScanDnsQuery || dnsQuery;

    // ── POST /api/free-scan ──────────────────────────────────────────────────
    // Public endpoint — no authentication required.
    // Runs a bounded six-module public snapshot and returns a deliberately
    // reduced eight-domain projection suitable for the /free-scan page.
    //
    // Rate limit: 5 free scans per IP per hour (IP stored hashed in api_rate_limits).
    // No D1 persistence — results are returned inline and discarded.
    // No R2 writes — no report is stored.
    //
    // Hidden findings, evidence, remediation, PDF and monitoring history are
    // not returned to anonymous callers. Full access still passes through the
    // canonical account + ownership-verification flow.
    if (request.method === "POST" && url.pathname === "/api/free-scan") {
      let body;
      try { body = await request.json(); } catch { return json({ error: "Invalid JSON body" }, 400); }

      const domain = (body.domain ?? "").trim().toLowerCase().replace(/^https?:\/\//, "").replace(/\/.*$/, "");
      if (!isValidDomain(domain)) {
        return json({ error: "Please enter a valid domain (e.g. example.com)" }, 400);
      }

      // Block obviously internal / reserved domains
      const BLOCKED_DOMAINS = ["localhost", "127.0.0.1", "0.0.0.0", "local"];
      if (BLOCKED_DOMAINS.some(b => domain === b || domain.endsWith("." + b))) {
        return json({ error: "That domain cannot be scanned" }, 400);
      }

      // SSRF: the string gate never resolves DNS, so a public-looking domain
      // whose A/AAAA record points at an internal address would otherwise be
      // fetched. Resolve first and refuse private/reserved targets. (Redirect-
      // time SSRF is handled per-hop inside safeFetch.)
      if (await resolvesToPrivateIp(domain, freeScanDnsQuery)) {
        return json({ error: "That domain cannot be scanned" }, 400);
      }

      // IP-based rate limit: 5 free scans per hour
      const clientIp = request.headers.get("CF-Connecting-IP") ||
                       request.headers.get("X-Forwarded-For")?.split(",")[0]?.trim() ||
                       "unknown";

      const rateLimitResult = await consumeApiRateLimit(
        env,
        [{ scope: "ip", scope_id: await rateLimitScopeId("freescan", clientIp) }],
        "free_scan",
        5,
        3600,
        { failClosed: true },
      );
      if (rateLimitResult) {
        // Honest copy: a free account raises limits and saves results — it is
        // not unlimited (free plan has monthly caps). Never overpromise here.
        return json({
          error: "Too many checks from this connection. Please wait an hour, or create a free account to save your results and monitor your domain.",
          code: "rate_limit_exceeded",
        }, 429);
      }

      // A botnet can rotate IPs while repeatedly targeting the same domain.
      // Keep a second fail-closed ceiling on the normalized target itself.
      const domainLimited = await consumeApiRateLimit(
        env,
        [{ scope: "domain", scope_id: await rateLimitScopeId("freescan-domain", domain) }],
        "free_scan_domain",
        3,
        3600,
        { failClosed: true },
      );
      if (domainLimited) {
        return json({
          error: "This domain has already been checked recently. Please wait an hour before trying again.",
          code: "rate_limit_exceeded",
        }, 429);
      }

      // Global backstop: the per-IP cap alone doesn't bound a distributed /
      // botnet attack that spreads guesses across many IPs to drive scan cost
      // (each scan fans out ~10-20 subrequests, several to external CT services
      // that can throttle our egress IP). This aggregate ceiling — fail-closed,
      // so it can't be evaporated during the D1 stress an attack causes — bounds
      // total free-scan volume regardless of source IP. Generous enough not to
      // affect legitimate traffic at beta scale; tune via the constant.
      const FREE_SCAN_GLOBAL_HOURLY_CAP = 500;
      const globalLimited = await consumeApiRateLimit(
        env,
        [{ scope: "global", scope_id: "free_scan_global" }],
        "free_scan_global",
        FREE_SCAN_GLOBAL_HOURLY_CAP,
        3600,
        { failClosed: true },
      );
      if (globalLimited) {
        return json({
          error: "Free checks are experiencing high demand right now. Please try again shortly, or create a free account to run your scan.",
          code: "rate_limit_exceeded",
        }, 429);
      }

      // One invocation owns one physical counter and one wall-clock deadline.
      // The six modules share DNS/CT caches. Deep fan-out modules are never
      // launched anonymously; the public projection says so explicitly.
      const scannedAt = new Date().toISOString();
      const physicalCounter = new PhysicalSubrequestCounter({
        limit: FREE_SCAN_SUBREQUEST_LIMIT,
        safetyMargin: 0,
      });
      const deadlineStartedAt = Date.now();
      const remainingMs = () => Math.max(
        0,
        FREE_SCAN_DEADLINE_MS - (Date.now() - deadlineStartedAt),
      );
      const deadline = new AbortController();
      const deadlineTimer = setTimeout(
        () => deadline.abort("free_scan_deadline_exhausted"),
        FREE_SCAN_DEADLINE_MS,
      );
      const dnsCache = makeDnsCache();
      const ctCache = createCertificateTransparencyCache({
        accounting: physicalCounter.contextFor("free_preview_ct", { signal: deadline.signal }),
        signal: deadline.signal,
        remainingMs,
      });
      const accountingFor = (module) =>
        physicalCounter.contextFor(`free_preview_${module}`, { signal: deadline.signal });

      let settlements;
      try {
        const [dnsR, sslR, headersR, emailR, subdomainsR, technologyR] =
          await Promise.allSettled([
            freeScanModuleRunners.dns(domain, {
              accounting: accountingFor("dns"), signal: deadline.signal, cache: dnsCache,
            }),
            freeScanModuleRunners.ssl(domain, {
              accounting: accountingFor("ssl"), signal: deadline.signal, ctCache,
            }),
            freeScanModuleRunners.headers(domain, {
              accounting: accountingFor("headers"), signal: deadline.signal,
              remainingMs,
            }),
            freeScanModuleRunners.email_security(domain, {
              accounting: accountingFor("email"), signal: deadline.signal, cache: dnsCache,
            }),
            freeScanModuleRunners.subdomains(domain, {
              accounting: accountingFor("subdomains"), signal: deadline.signal,
              cache: dnsCache, ctCache,
            }),
            freeScanModuleRunners.technology_detection(domain, {
              accounting: accountingFor("technology"), signal: deadline.signal,
            }),
          ]);
        settlements = {
          dns: dnsR,
          ssl: sslR,
          headers: headersR,
          email_security: emailR,
          subdomains: subdomainsR,
          technology_detection: technologyR,
        };
      } finally {
        clearTimeout(deadlineTimer);
      }

      const freeScanEvidence = buildFreeScanEvidence(settlements);

      // Academy slug mapping — same logic as frontend getAcademyArticleForFinding
      // We resolve it server-side so the API response is self-contained.
      const FINDING_ACADEMY_MAP = {
        email_missing_spf:                       "spf-explained",
        email_intel_spf_missing:                 "spf-explained",
        email_intel_spf_permissive:              "spf-explained",
        email_missing_dmarc:                     "dmarc-explained",
        email_intel_dmarc_missing:               "dmarc-explained",
        email_intel_dmarc_reporting_only:        "dmarc-explained",
        email_dmarc_policy_none:                 "dmarc-explained",
        email_weak_dmarc:                        "dmarc-explained",
        email_dkim_not_detected:                 "dkim-explained",
        email_intel_dkim_not_found:              "dkim-explained",
        dnssec_not_enabled:                      "dnssec-explained",
        dnssec_misconfigured:                    "dnssec-explained",
        header_missing_strict_transport_security:"hsts-explained",
        header_weak_hsts:                        "hsts-explained",
        dse_hsts_short_maxage:                   "hsts-explained",
        header_missing_content_security_policy:  "csp-explained",
        csp_weak_policy:                         "csp-explained",
        security_headers_not_observed:           "csp-explained",
        subdomain_takeover:                      "what-is-subdomain-takeover",
        subdomain_takeover_risk:                 "what-is-subdomain-takeover",
        cloud_storage_exposure_observed:         "public-cloud-storage-risks",
        cloud_storage_public_listing:            "public-cloud-storage-risks",
        admin_surface_critical:                  "what-is-attack-surface-management",
        admin_surface_high:                      "what-is-attack-surface-management",
      };

      function resolveAcademySlug(findingId) {
        if (!findingId) return null;
        if (FINDING_ACADEMY_MAP[findingId]) return FINDING_ACADEMY_MAP[findingId];
        // prefix match (strip trailing _segments one at a time)
        const parts = findingId.split("_");
        for (let len = parts.length - 1; len >= 1; len--) {
          const prefix = parts.slice(0, len).join("_");
          if (FINDING_ACADEMY_MAP[prefix]) return FINDING_ACADEMY_MAP[prefix];
        }
        return null;
      }

      return json(buildFreeScanPreview({
        domain,
        scannedAt,
        freeScanEvidence,
        resolveAcademySlug,
        execution: physicalCounter.snapshot(),
      }));
    }

    // ── GET /api/workspaces/:id/subscription ─────────────────────────────────
    // Returns the full subscription state for a workspace, including trial
    // status, plan, and computed fields useful for the Billing/Subscription UI.
    //
    // Response:
    //   { subscription_active, plan, status, trial_active, trial_remaining_days,
    //     trial_start, trial_end, current_period_start, current_period_end,
    //     billing_interval, cancel_at_period_end, stripe_subscription_id }
    const wsSubMatch = url.pathname.match(/^\/api\/workspaces\/([^/]+)\/subscription$/);
    if (wsSubMatch && request.method === "GET") {
      const wsId = wsSubMatch[1];
      const user = await requireAuth(request, env);
      if (!user) return json({ error: "Unauthorized" }, 401);
      const access = await requireWorkspaceRole(user, wsId, "workspace:read", env);
      if (!access) return json({ error: "Forbidden" }, 403);

      try {
        const sub = await getWorkspaceSubscription(wsId, env);
        const trialActive       = isTrialActive(sub);
        const subscriptionActive = isSubscriptionActive(sub);
        const trialRemainingDays = getTrialRemainingDays(sub);
        const grace             = getPaymentGraceState(sub);

        // Effective plan: trial plan if trialing, paid plan while active OR
        // inside the payment grace window (matches getUserPlan so the billing
        // UI and runtime entitlements never disagree), else free.
        let effectivePlan = "free";
        if (sub) {
          if (trialActive) {
            effectivePlan = normalizePlan(sub.plan ?? TRIAL_PLAN);
          } else if (subscriptionActive || grace.active) {
            effectivePlan = normalizePlan(sub.plan);
          }
        }

        // Trial-aware limits: the 14-day trial borrows the professional feature
        // set but caps monitored domains at the trial allowance — the SAME
        // override the domain-add enforcement applies, so the billing UI can
        // never display headroom the backend would refuse.
        const baseLimits = getPlanLimits(effectivePlan);
        const trialDomains = trialActive ? getEffectiveDomainLimit(effectivePlan, true) : null;
        const limits = trialActive
          ? { ...baseLimits, domains: trialDomains, domains_per_workspace: trialDomains }
          : baseLimits;
        const features = getPlanFeatures(effectivePlan);

        return json({
          plan:                 effectivePlan,
          status:               sub?.subscription_status ?? (sub ? sub.status : "free"),
          subscription_active:  trialActive || subscriptionActive || grace.active,
          trial_active:         trialActive,
          trial_remaining_days: trialRemainingDays,
          trial_start:          sub?.trial_start ?? null,
          trial_end:            sub?.trial_end ?? null,
          current_period_start: sub?.current_period_start ?? null,
          current_period_end:   sub?.current_period_end ?? sub?.expires_at ?? null,
          billing_interval:     sub?.billing_interval ?? "monthly",
          cancel_at_period_end: sub?.cancel_at_period_end === 1 || sub?.cancel_at_period_end === true,
          cancelled_at:         sub?.cancelled_at ?? null,
          grace_period_active:  grace.active,
          grace_period_ends_at: grace.ends_at,
          stripe_subscription_id: sub?.stripe_subscription_id ?? null,
          limits,
          features,
        });
      } catch (e) {
        return serverError("api", e);
      }
    }

    // ── GET /api/plans ────────────────────────────────────────────────────────
    // Public static plan metadata — pricing, limits, feature sets.
    // Alias for GET /api/billing/plans with a cleaner path.
    // No auth required.
    if (request.method === "GET" && url.pathname === "/api/plans") {
      return json({ plans: getPublicBillingPlans() });
    }

    // Create a Stripe billing-portal session for a customer. Shared by the
    // portal route and the B3 checkout guard (plan changes for active paid
    // subscribers happen in the portal, never via a second checkout).
    async function createStripeBillingPortalSession(stripeCustomerId, returnUrl) {
      const portalParams = new URLSearchParams();
      portalParams.set("customer",   stripeCustomerId);
      portalParams.set("return_url", returnUrl);
      try {
        const stripeRes = await fetch("https://api.stripe.com/v1/billing_portal/sessions", {
          method: "POST",
          headers: {
            "Authorization": `Bearer ${env.STRIPE_SECRET_KEY}`,
            "Content-Type":  "application/x-www-form-urlencoded",
          },
          body: portalParams.toString(),
        });
        const stripeData = await stripeRes.json();
        if (!stripeRes.ok) {
          console.error("[workspace-billing/portal] Stripe API error", {
            status: stripeRes.status,
            type: stripeData?.error?.type ?? null,
            code: stripeData?.error?.code ?? null,
          });
          return { ok: false, error: "stripe_api_error", message: "Stripe Billing Portal Session creation failed. Please try again." };
        }
        return { ok: true, session: stripeData };
      } catch (e) {
        console.error(`[workspace-billing/portal] ${e?.message ?? e}`);
        return { ok: false, error: "stripe_request_failed", message: "Could not reach Stripe. Please try again." };
      }
    }

    // ── POST /api/workspaces/:id/billing/checkout ─────────────────────────────
    // Workspace-scoped Stripe Checkout Session. Workspace owner only.
    // Body: { "plan": "starter|professional|business", "interval": "monthly|annual" }
    // interval defaults to "monthly". success_url and cancel_url are hardcoded.
    // Returns: { "url": "https://checkout.stripe.com/..." }
    const wsCheckoutMatch = url.pathname.match(/^\/api\/workspaces\/([^/]+)\/billing\/checkout$/);
    if (wsCheckoutMatch && request.method === "POST") {
      const wsId = wsCheckoutMatch[1];
      const user = await requireAuth(request, env);
      if (!user) return json({ error: "Unauthorized" }, 401);
      if (user.api_token_id) {
        await auditApiTokenSessionRouteDenied(env, user, request);
        return json({ error: "Session authentication required" }, 403);
      }

      // Workspace owner check: only the workspace owner may initiate billing.
      const access = await requireWorkspaceRole(user, wsId, "billing:manage", env);
      if (!access) return json({ error: "Forbidden", message: "Workspace owner required for billing." }, 403);

      let body;
      try { body = await request.json(); } catch { return json({ error: "Invalid JSON body" }, 400); }

      // Enterprise plan requires sales contact — never self-serve checkout.
      const rawPlan = String(body.plan || "").trim().toLowerCase();
      if (rawPlan === "enterprise") {
        return json({
          error: "contact_sales",
          message: "Enterprise plans require a sales conversation. Contact us at sales@cybermeters.com.",
          contact_url: "mailto:sales@cybermeters.com",
        }, 400);
      }

      const parsedPlan = parseCheckoutPlan(rawPlan);
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

      // B3 (founder-approved 21 Jul 2026): a customer who ALREADY has an
      // active paid Stripe subscription must change plan through the Stripe
      // billing portal. A fresh subscription-mode Checkout Session always
      // creates a NEW subscription — it never switches the existing one, and
      // nothing in the checkout or webhook chain cancels the old sub — so a
      // second live subscription would stack and the customer would be charged
      // for BOTH. Structural guard: return a billing-portal session (Stripe
      // switches the EXISTING subscription there, with clean proration)
      // instead of a checkout session. Trial / free / manual rows carry no
      // stripe_subscription_id and keep the fresh-checkout path. Returning the
      // portal URL (same { url } shape) also self-heals older cached frontends.
      const currentSub = await getWorkspaceSubscription(wsId, env);
      if (shouldRoutePlanChangeToPortal(currentSub)) {
        const reqOrigin = new URL(request.url).origin;
        const portalReturnOrigin = env.FRONTEND_URL || reqOrigin.replace("cybermeters-platform.ttrnn47.workers.dev", "cybermeters.com");
        const portal = await createStripeBillingPortalSession(currentSub.stripe_customer_id, `${portalReturnOrigin}/billing`);
        if (!portal.ok) {
          return json({ error: portal.error, message: portal.message }, 502);
        }
        await createAuditEvent(env, {
          user_id:      user.id,
          workspace_id: wsId,
          event_type:   "billing_checkout_routed_to_portal",
          entity_type:  "stripe_billing_portal_session",
          entity_id:    portal.session.id,
          description:  `Checkout request for ${requestedPlan} (${interval}) routed to the billing portal — active paid subscription exists; plan changes go through the portal so a second subscription can never stack`,
          metadata:     {
            requested_plan:         requestedPlan,
            requested_interval:     interval,
            subscription_row_id:    currentSub.id ?? null,
            stripe_subscription_id: currentSub.stripe_subscription_id ?? null,
            stripe_session_id:      portal.session.id,
            workspace_id:           wsId,
          },
        });
        return json({
          url:        portal.session.url,
          session_id: portal.session.id,
          portal:     true,
          reason:     "plan_change_via_portal",
          message:    "You already have an active subscription. Plan changes are made in the Stripe billing portal, which adjusts your existing subscription with fair proration.",
        }, 200);
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

      // Resolve the billing owner for this workspace (workspace.owner_user_id).
      const ownerUserId = await getWorkspaceBillingUserId(wsId, user.id, env);

      // Lookup existing subscription for this owner to reuse Stripe customer if present.
      let existingSub = null;
      try {
        existingSub = await env.cybermeters_db
          .prepare(
            `SELECT id, stripe_customer_id
             FROM subscriptions
             WHERE owner_user_id = ?
             ORDER BY COALESCE(updated_at, created_at) DESC
             LIMIT 1`
          )
          .bind(ownerUserId)
          .first();
      } catch { /* continue without existing customer */ }

      // Hardcoded success/cancel URLs — prevents open redirect via client-supplied URLs.
      const origin = new URL(request.url).origin;
      // Use FRONTEND_URL env var if set (Cloudflare Pages URL), else derive from Worker origin.
      const frontendOrigin = env.FRONTEND_URL || origin.replace("cybermeters-platform.ttrnn47.workers.dev", "cybermeters.com");
      const successUrl = `${frontendOrigin}/billing?success=true`;
      const cancelUrl  = `${frontendOrigin}/billing?canceled=true`;

      const params = new URLSearchParams();
      params.set("mode",                    "subscription");
      params.set("line_items[0][price]",    priceResolution.price_id);
      params.set("line_items[0][quantity]", "1");
      params.set("success_url",             successUrl);
      params.set("cancel_url",              cancelUrl);
      params.set("metadata[user_id]",       String(ownerUserId));
      params.set("metadata[plan]",          requestedPlan);
      params.set("metadata[interval]",      interval);
      params.set("metadata[workspace_id]",  wsId);
      params.set("subscription_data[metadata][user_id]",    String(ownerUserId));
      params.set("subscription_data[metadata][plan]",       requestedPlan);
      params.set("subscription_data[metadata][interval]",   interval);
      params.set("subscription_data[metadata][workspace_id]", wsId);
      params.set("allow_promotion_codes", "true");

      // B2 (founder-approved 21 Jul 2026): mandatory Terms acceptance plus the
      // explicit immediate-start / 14-day cooling-off waiver, collected by
      // Stripe on the checkout page and recorded on the session — see
      // applyCheckoutConsentParams (engines/stripe.js) for the approved wording
      // and the webhook audit trail for the recorded acceptance. Requires the
      // Terms of Service URL to be set in the Stripe account's public business
      // settings (founder dashboard action; session creation fails without it).
      applyCheckoutConsentParams(params);

      if (existingSub?.stripe_customer_id) {
        params.set("customer", existingSub.stripe_customer_id);
      } else {
        params.set("customer_email", user.email);
      }

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
          console.error("[workspace-billing/checkout] Stripe API error", {
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
        console.error(`[workspace-billing/checkout] ${e?.message ?? e}`);
        return json({
          error:   "stripe_request_failed",
          message: "Could not reach Stripe. Please try again.",
        }, 502);
      }

      await createAuditEvent(env, {
        user_id:     user.id,
        workspace_id: wsId,
        event_type:  "billing_checkout_session_created",
        entity_type: "stripe_checkout_session",
        entity_id:   stripeSession.id,
        description: `Workspace checkout session created for ${requestedPlan} (${interval})`,
        metadata:    { plan: requestedPlan, interval, stripe_session_id: stripeSession.id, workspace_id: wsId },
      });

      return json({ url: stripeSession.url, session_id: stripeSession.id }, 200);
    }

    // ── POST /api/workspaces/:id/billing/portal ───────────────────────────────
    // Opens a Stripe Billing Portal for workspace subscription management.
    // Workspace owner only. Requires an existing Stripe customer.
    // Returns: { "url": "https://billing.stripe.com/..." }
    const wsPortalMatch = url.pathname.match(/^\/api\/workspaces\/([^/]+)\/billing\/portal$/);
    if (wsPortalMatch && request.method === "POST") {
      const wsId = wsPortalMatch[1];
      const user = await requireAuth(request, env);
      if (!user) return json({ error: "Unauthorized" }, 401);
      if (user.api_token_id) {
        await auditApiTokenSessionRouteDenied(env, user, request);
        return json({ error: "Session authentication required" }, 403);
      }

      const access = await requireWorkspaceRole(user, wsId, "billing:manage", env);
      if (!access) return json({ error: "Forbidden", message: "Workspace owner required for billing." }, 403);

      const stripeConfig = validateStripeSecretConfig(env);
      if (!stripeConfig.ok) {
        return json({
          error: stripeConfig.error,
          missing: stripeConfig.missing,
          message: "Stripe billing configuration is not ready for Customer Portal.",
        }, 503);
      }

      const ownerUserId = await getWorkspaceBillingUserId(wsId, user.id, env);

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
          .bind(ownerUserId)
          .first();
      } catch (e) {
        return serverError("workspace-billing/portal-subscription", e, "Unable to load billing information.");
      }

      if (!subscription) {
        return json({ error: "subscription_not_found", message: "No active subscription found for this workspace." }, 404);
      }
      if (!subscription.stripe_customer_id) {
        return json({ error: "stripe_customer_missing", message: "No Stripe customer on file. Complete a checkout first." }, 409);
      }

      const origin = new URL(request.url).origin;
      const frontendOrigin = env.FRONTEND_URL || origin.replace("cybermeters-platform.ttrnn47.workers.dev", "cybermeters.com");
      const returnUrl = `${frontendOrigin}/billing`;

      const portal = await createStripeBillingPortalSession(subscription.stripe_customer_id, returnUrl);
      if (!portal.ok) {
        return json({ error: portal.error, message: portal.message }, 502);
      }
      const portalSession = portal.session;

      await createAuditEvent(env, {
        user_id:      user.id,
        workspace_id: wsId,
        event_type:   "billing_portal_opened",
        entity_type:  "stripe_billing_portal_session",
        entity_id:    portalSession.id,
        description:  "Workspace Stripe billing portal session created",
        metadata:     { subscription_id: subscription.id, stripe_session_id: portalSession.id, workspace_id: wsId },
      });

      return json({ url: portalSession.url, session_id: portalSession.id }, 200);
    }


  return null;
}
