// ── Account routes ──
// Account onboarding-state/bootstrap, profile + company, subscription/usage/
// limits views, admin subscription list, API tokens, login history, sessions,
// GDPR export, account delete-request and the platform accuracy QA endpoint.
// Extracted near-verbatim from index.js (router split, Phase 2 PR #18).
// Receives the per-request routeCtx from index.js; returns a Response when a
// route matches, or null so the main router continues.
import { PLAN_FEATURES, getEffectivePlan, getPlanFeatures, hasFeatureEntitlement, normalizeBillingInterval, normalizePlan } from "../engines/entitlements.js";
import { validateBrandingInput } from "../engines/report-branding.js";
import { validateFindingEvidence } from "../engines/findings.js";
import { getEntitlementUsage, getPlanContext, getPlanLimits, getUpgradeRecommendation, planLimitExceeded } from "../engines/plan-usage.js";
import { auditApiTokenSessionRouteDenied } from "../engines/subscription-state.js";
import { generateApiToken, hashToken } from "../lib/auth-crypto.js";
import { createAuditEvent } from "../lib/events.js";
import { createId, isValidEmail } from "../lib/util.js";

export async function accountRoutes(rctx) {
  const { request, env, url, json, serverError, requestId,
          requireAuth, requireWorkspaceRole, requireWorkspaceAccess,
          getAccessibleWorkspaceIds, isPlatformAdmin, evaluateRegressionFixtures } = rctx;

	    // ── GET /api/account/onboarding-state ───────────────────────────────
	    // Lightweight first-workspace/first-scan state for session users.
	    // Returns counts and booleans only; no workspace IDs are exposed.
	    if (request.method === "GET" && url.pathname === "/api/account/onboarding-state") {
	      const user = await requireAuth(request, env);
	      if (!user) return json({ error: "Unauthorized" }, 401);
	      if (user.api_token_id) return json({ error: "Session authentication required" }, 403);

	      try {
	        const workspaceIds = await getAccessibleWorkspaceIds(user, env);
		        const workspaceCount = workspaceIds.length;
		        let domainCount = 0;
		        let completedScanCount = 0;
		        let reviewedResultsCount = 0;

	        if (workspaceCount > 0) {
	          const wsPlaceholders = workspaceIds.map(() => "?").join(",");
	          const domainRow = await env.cybermeters_db
	            .prepare(
	              `SELECT COUNT(DISTINCT domain_id) AS count
	               FROM workspace_domains
	               WHERE workspace_id IN (${wsPlaceholders})`
	            )
	            .bind(...workspaceIds)
	            .first();
	          domainCount = Number(domainRow?.count ?? 0);

	          const scanRow = await env.cybermeters_db
	            .prepare(
	              `SELECT COUNT(DISTINCT s.id) AS count
	               FROM scans s
	               LEFT JOIN workspace_domains wd ON wd.domain_id = s.domain_id
	               WHERE s.status = 'completed'
	                 AND (
	                   s.workspace_id IN (${wsPlaceholders})
	                   OR (s.workspace_id IS NULL AND wd.workspace_id IN (${wsPlaceholders}))
	                 )`
	            )
	            .bind(...workspaceIds, ...workspaceIds)
		            .first();
		          completedScanCount = Number(scanRow?.count ?? 0);

		          const reportRow = await env.cybermeters_db
		            .prepare(
		              `SELECT COUNT(*) AS count
		               FROM workspace_reports
		               WHERE workspace_id IN (${wsPlaceholders})
		                 AND status = 'completed'`
		            )
		            .bind(...workspaceIds)
		            .first();
		          reviewedResultsCount = Number(reportRow?.count ?? 0);
		        }

	        const hasWorkspaces = workspaceCount > 0;
	        const hasDomains = domainCount > 0;
	        const hasCompletedScan = completedScanCount > 0;
		        const hasReviewedResults = reviewedResultsCount > 0;
	        const nextStep =
	          !hasWorkspaces ? "create_workspace" :
	          !hasDomains ? "add_domain" :
	          !hasCompletedScan ? "run_first_scan" :
	          !hasReviewedResults ? "review_results" : "complete";

	        createAuditEvent(env, {
	          user_id:     user.id,
	          event_type:  "onboarding_state_viewed",
	          entity_type: "user",
	          entity_id:   user.id,
	          description: "User viewed onboarding state",
	          metadata:    {
	            workspace_count: workspaceCount,
	            domain_count: domainCount,
	            completed_scan_count: completedScanCount,
	            next_step: nextStep,
	          },
	        }).catch(() => {});

	        return json({
	          has_workspaces: hasWorkspaces,
	          workspace_count: workspaceCount,
	          has_domains: hasDomains,
	          domain_count: domainCount,
	          has_completed_scan: hasCompletedScan,
	          completed_scan_count: completedScanCount,
	          next_step: nextStep,
	          progress: {
	            create_workspace: hasWorkspaces,
	            add_domain: hasDomains,
	            run_scan: hasCompletedScan,
	            review_results: hasReviewedResults,
	          },
	        });
	      } catch (e) {
	        return serverError("api", e);
	      }
	    }

	    // ── POST /api/account/bootstrap ──────────────────────────────────────
	    // Idempotent workspace bootstrap for new users.
	    //
	    // Called by the frontend after login when the user has no workspaces:
	    //   - If the user already has at least one workspace → returns it (no-op).
	    //   - If the user has no workspaces → auto-creates one named from their
	    //     email domain or display name and seeds the owner membership row.
	    //
	    // This gives every beta user a working workspace without requiring a manual
	    // "Create Workspace" step before they can do anything useful.
	    //
	    // Security:
	    //   - Session auth only (no API tokens).
	    //   - Still respects plan limits: free users get 1 workspace, which this
	    //     creates — so bootstrap is always within entitlement for new accounts.
	    if (request.method === "POST" && url.pathname === "/api/account/bootstrap") {
	      const user = await requireAuth(request, env);
	      if (!user) return json({ error: "Unauthorized" }, 401);
	      if (user.api_token_id) return json({ error: "Session authentication required" }, 403);

	      try {
	        // Check for existing workspaces the user owns or is a member of.
	        const existingIds = await getAccessibleWorkspaceIds(user, env);
	        if (existingIds.length > 0) {
	          // Already has workspaces — return the first one (no-op).
	          const placeholders = existingIds.map(() => "?").join(",");
	          const first = await env.cybermeters_db
	            .prepare(
	              `SELECT id, name, created_at FROM workspaces
	               WHERE id IN (${placeholders})
	               ORDER BY created_at ASC LIMIT 1`
	            )
	            .bind(...existingIds)
	            .first();
	          return json({ workspace: first, created: false });
	        }

	        // No workspaces — derive a friendly default name.
	        // Use display name if set, otherwise use the email domain capitalised.
	        let bootstrapName = "My Workspace";
	        if (user.name && user.name.trim().length > 0) {
	          bootstrapName = `${user.name.trim()}'s Workspace`;
	        } else if (user.email) {
	          const domain = user.email.split("@")[1] ?? "";
	          const brand  = domain.split(".")[0] ?? "";
	          if (brand.length > 0) {
	            bootstrapName = brand.charAt(0).toUpperCase() + brand.slice(1).toLowerCase() + " Workspace";
	          }
	        }

	        const bsId        = `workspace_${crypto.randomUUID()}`;
	        const bsCreatedAt = new Date().toISOString();

	        await env.cybermeters_db
	          .prepare(`INSERT INTO workspaces (id, name, owner_user_id, created_at) VALUES (?, ?, ?, ?)`)
	          .bind(bsId, bootstrapName, user.id, bsCreatedAt)
	          .run();

	        await env.cybermeters_db
	          .prepare(
	            `INSERT OR IGNORE INTO workspace_members (id, workspace_id, user_id, role, created_at)
	             VALUES (?, ?, ?, 'owner', datetime('now'))`
	          )
	          .bind(createId("wm"), bsId, user.id)
	          .run();

	        await createAuditEvent(env, {
	          workspace_id: bsId,
	          user_id:      user.id,
	          event_type:   "workspace_bootstrapped",
	          entity_type:  "workspace",
	          entity_id:    bsId,
	          description:  `Default workspace "${bootstrapName}" auto-created for ${user.email}`,
	          metadata:     { workspace_name: bootstrapName, bootstrap: true },
	        }).catch(() => {});

	        return json({ workspace: { id: bsId, name: bootstrapName, created_at: bsCreatedAt }, created: true }, 201);
	      } catch (e) {
	        return serverError("api", e);
	      }
	    }

	    // ── GET /api/account/profile ─────────────────────────────────────────
	    // Returns the authenticated account, company profile, and subscription foundation.
	    if (request.method === "GET" && url.pathname === "/api/account/profile") {
      const user = await requireAuth(request, env);
      if (!user) return json({ error: "Unauthorized" }, 401);
      try {
        const [profile, sub] = await Promise.all([
          env.cybermeters_db
            .prepare(
              `SELECT id, company_name, website, industry, company_size,
                      contact_email, contact_name, created_at, updated_at
               FROM customer_profiles
               WHERE owner_user_id = ?`
            )
            .bind(user.id)
            .first(),
          env.cybermeters_db
            .prepare(
              `SELECT id, plan, subscription_status AS status,
                      'stripe' AS billing_provider,
                      NULL AS billing_email, NULL AS trial_ends_at,
                      current_period_end, created_at, updated_at
               FROM subscriptions
               WHERE owner_user_id = ?
               ORDER BY COALESCE(updated_at, created_at) DESC
               LIMIT 1`
            )
            .bind(user.id)
            .first(),
        ]);
        const plan = await getEffectivePlan(user.id, env);
        return json({
          user: {
            id:    user.id,
            email: user.email,
            name:  user.name,
            plan,
          },
          company: profile ?? null,
          subscription: sub ? { ...sub, plan } : {
            plan,
            status:           "active",
            billing_provider: "manual",
            billing_email:    user.email,
          },
        });
      } catch (e) {
        return serverError("api", e);
      }
    }

    // ── PATCH /api/account/profile ───────────────────────────────────────
    // Updates account profile fields only. Email remains read-only in v1.
    if (request.method === "PATCH" && url.pathname === "/api/account/profile") {
      const user = await requireAuth(request, env);
      if (!user) return json({ error: "Unauthorized" }, 401);
      // Profile mutation is an account-control action; API tokens are data-plane only.
      if (user.api_token_id) {
        await auditApiTokenSessionRouteDenied(env, user, request);
        return json({ error: "Session authentication required" }, 403);
      }
      let body;
      try { body = await request.json(); } catch { return json({ error: "Invalid JSON body" }, 400); }

      const name = typeof body.name === "string" ? body.name.trim() : "";
      if (!name) return json({ error: "name is required" }, 400);
      if (name.length > 120) return json({ error: "name is too long" }, 400);

      try {
        await env.cybermeters_db
          .prepare("UPDATE users SET name = ? WHERE id = ?")
          .bind(name, user.id)
          .run();

        const plan = await getEffectivePlan(user.id, env);
        await createAuditEvent(env, {
          user_id:     user.id,
          event_type:  "account_profile_updated",
          entity_type: "user",
          entity_id:   user.id,
          description: "Account profile updated",
          metadata:    { changed_fields: ["name"] },
        });
        return json({
          user: {
            id:    user.id,
            email: user.email,
            name,
            plan,
          },
        });
      } catch (e) {
        return serverError("api", e);
      }
    }

    // ── GET /api/account/company ─────────────────────────────────────────
    if (request.method === "GET" && url.pathname === "/api/account/company") {
      const user = await requireAuth(request, env);
      if (!user) return json({ error: "Unauthorized" }, 401);
      try {
        const company = await env.cybermeters_db
          .prepare(
            `SELECT id, company_name, website, industry, company_size,
                    contact_email, contact_name, created_at, updated_at
             FROM customer_profiles
             WHERE owner_user_id = ?`
          )
          .bind(user.id)
          .first();
        return json({ company: company ?? null });
      } catch (e) {
        return serverError("api", e);
      }
    }

    // ── PUT /api/account/company ─────────────────────────────────────────
    if (request.method === "PUT" && url.pathname === "/api/account/company") {
      const user = await requireAuth(request, env);
      if (!user) return json({ error: "Unauthorized" }, 401);
      // Company profile mutation is an account-control action; require a session.
      if (user.api_token_id) {
        await auditApiTokenSessionRouteDenied(env, user, request);
        return json({ error: "Session authentication required" }, 403);
      }
      let body;
      try { body = await request.json(); } catch { return json({ error: "Invalid JSON body" }, 400); }

      const company_name  = (body.company_name  || "").trim();
      const website       = (body.website       || "").trim() || null;
      const industry      = (body.industry      || "").trim() || null;
      const company_size  = (body.company_size  || "").trim() || null;
      const contact_name  = (body.contact_name  || "").trim() || null;
      const contact_email = (body.contact_email || "").trim().toLowerCase() || null;

      if (!company_name) return json({ error: "company_name is required" }, 400);
      if (company_name.length > 200) return json({ error: "company_name is too long" }, 400);
      if (website && website.length > 300) return json({ error: "website is too long" }, 400);
      if (contact_email && !isValidEmail(contact_email)) {
        return json({ error: "contact_email must be a valid email address" }, 400);
      }

      const VALID_SIZES = ["1-10", "11-50", "51-200", "201-1000", "1000+"];
      if (company_size && !VALID_SIZES.includes(company_size)) {
        return json({ error: `company_size must be one of: ${VALID_SIZES.join(", ")}` }, 400);
      }

      try {
        const companyId = createId("cust");
        await env.cybermeters_db
          .prepare(
            `INSERT INTO customer_profiles
               (id, owner_user_id, company_name, website, industry, company_size,
                contact_email, contact_name, created_at, updated_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, datetime('now'), datetime('now'))
             ON CONFLICT(owner_user_id) DO UPDATE SET
               company_name  = excluded.company_name,
               website       = excluded.website,
               industry      = excluded.industry,
               company_size  = excluded.company_size,
               contact_email = excluded.contact_email,
               contact_name  = excluded.contact_name,
               updated_at    = datetime('now')`
          )
          .bind(companyId, user.id, company_name, website, industry, company_size, contact_email, contact_name)
          .run();

        const company = await env.cybermeters_db
          .prepare(
            `SELECT id, company_name, website, industry, company_size,
                    contact_email, contact_name, created_at, updated_at
             FROM customer_profiles
             WHERE owner_user_id = ?`
          )
          .bind(user.id)
          .first();

        await createAuditEvent(env, {
          user_id:     user.id,
          event_type:  "company_profile_updated",
          entity_type: "customer_profile",
          entity_id:   company?.id ?? companyId,
          description: "Company profile updated",
          metadata:    {
            changed_fields: ["company_name", "website", "industry", "company_size", "contact_email", "contact_name"],
          },
        });
        return json({ company });
      } catch (e) {
        return serverError("api", e);
      }
    }

    // ── GET /api/account/report-branding ─────────────────────────────────
    // White-label branding for reports (MSP "send with my own logo"). Reads
    // the account-level brand + whether the plan may switch it on.
    if (request.method === "GET" && url.pathname === "/api/account/report-branding") {
      const user = await requireAuth(request, env);
      if (!user) return json({ error: "Unauthorized" }, 401);
      try {
        const row = await env.cybermeters_db
          .prepare(
            `SELECT company_name, brand_logo, brand_accent, report_white_label
             FROM customer_profiles WHERE owner_user_id = ?`
          )
          .bind(user.id)
          .first();
        const plan = await getEffectivePlan(user.id, env);
        return json({
          branding: {
            company_name:       row?.company_name ?? null,
            brand_logo:         row?.brand_logo ?? null,
            brand_accent:       row?.brand_accent ?? null,
            report_white_label: row ? !!row.report_white_label : false,
          },
          white_label_available: hasFeatureEntitlement(plan, "white_label"),
          has_company_profile:   !!row,
        });
      } catch (e) {
        return serverError("api", e);
      }
    }

    // ── PUT /api/account/report-branding ─────────────────────────────────
    // Set the report brand. Turning white-label ON requires the white_label
    // entitlement (Business+); logo/accent may be staged on any plan.
    if (request.method === "PUT" && url.pathname === "/api/account/report-branding") {
      const user = await requireAuth(request, env);
      if (!user) return json({ error: "Unauthorized" }, 401);
      if (user.api_token_id) {
        await auditApiTokenSessionRouteDenied(env, user, request);
        return json({ error: "Session authentication required" }, 403);
      }
      let body;
      try { body = await request.json(); } catch { return json({ error: "Invalid JSON body" }, 400); }

      const parsed = validateBrandingInput(body);
      if (!parsed.ok) return json({ error: parsed.error }, 400);
      const b = parsed.value;

      // Enforce the plan gate only when switching white-label ON.
      if (b.report_white_label === 1) {
        const plan = await getEffectivePlan(user.id, env);
        if (!hasFeatureEntitlement(plan, "white_label")) {
          return json({
            error:         "plan_feature_required",
            feature:       "white_label",
            required_plan: "business",
            upgrade_url:   "/billing",
          }, 403);
        }
      }

      try {
        // Branding lives on the company profile — it must exist first so the
        // report always has a company name to lead with.
        const existing = await env.cybermeters_db
          .prepare(`SELECT id FROM customer_profiles WHERE owner_user_id = ?`)
          .bind(user.id)
          .first();
        if (!existing) {
          return json({ error: "Set your company profile first", need_company_profile: true }, 409);
        }

        const sets = [], binds = [];
        if ("brand_logo" in b)         { sets.push("brand_logo = ?");         binds.push(b.brand_logo); }
        if ("brand_accent" in b)       { sets.push("brand_accent = ?");       binds.push(b.brand_accent); }
        if ("report_white_label" in b) { sets.push("report_white_label = ?"); binds.push(b.report_white_label); }
        if (sets.length) {
          sets.push("updated_at = datetime('now')");
          binds.push(user.id);
          await env.cybermeters_db
            .prepare(`UPDATE customer_profiles SET ${sets.join(", ")} WHERE owner_user_id = ?`)
            .bind(...binds)
            .run();
        }

        const row = await env.cybermeters_db
          .prepare(
            `SELECT company_name, brand_logo, brand_accent, report_white_label
             FROM customer_profiles WHERE owner_user_id = ?`
          )
          .bind(user.id)
          .first();

        await createAuditEvent(env, {
          user_id:     user.id,
          event_type:  "report_branding_updated",
          entity_type: "customer_profile",
          entity_id:   existing.id,
          description: "Report white-label branding updated",
          metadata:    { report_white_label: row ? !!row.report_white_label : false, has_logo: !!row?.brand_logo },
        });

        return json({
          branding: {
            company_name:       row?.company_name ?? null,
            brand_logo:         row?.brand_logo ?? null,
            brand_accent:       row?.brand_accent ?? null,
            report_white_label: row ? !!row.report_white_label : false,
          },
        });
      } catch (e) {
        return serverError("api", e);
      }
    }

    // ── GET /api/account/subscription ────────────────────────────────────
    if (request.method === "GET" && url.pathname === "/api/account/subscription") {
      const user = await requireAuth(request, env);
      if (!user) return json({ error: "Unauthorized" }, 401);
      try {
        const sub = await env.cybermeters_db
          .prepare(
            `SELECT id, plan, subscription_status AS status,
                    billing_interval AS billing_cycle,
                    'stripe' AS billing_provider,
                    NULL AS billing_email, NULL AS trial_ends_at,
                    current_period_end, created_at, updated_at
             FROM subscriptions
             WHERE owner_user_id = ?
             ORDER BY COALESCE(updated_at, created_at) DESC
             LIMIT 1`
          )
          .bind(user.id)
          .first();

        const plan = await getEffectivePlan(user.id, env);
        return json({
          subscription: sub ? { ...sub, plan, billing_cycle: normalizeBillingInterval(sub.billing_cycle) } : {
            plan,
            status:             "active",
            billing_cycle:      "monthly",
            billing_provider:   "manual",
            billing_email:      user.email,
            trial_ends_at:      null,
            current_period_end: null,
          },
        });
      } catch (e) {
        return serverError("api", e);
      }
    }

    // ── GET /api/account/subscription/features ──────────────────────────
    // Read-only feature entitlement metadata. This exposes the static
    // PLAN_FEATURES result for the effective plan; it does not gate features.
    if (request.method === "GET" && url.pathname === "/api/account/subscription/features") {
      const user = await requireAuth(request, env);
      if (!user) return json({ error: "Unauthorized" }, 401);
      try {
        const plan = await getEffectivePlan(user.id, env);
        return json({
          plan,
          features: getPlanFeatures(plan),
        });
      } catch (e) {
        return serverError("api", e);
      }
    }

    // ── GET /api/account/usage ───────────────────────────────────────────
    // Returns: { plan, limits, usage, percentages, upgrade_signals }
    // percentages: per-resource % of plan limit used (omitted for unlimited).
    // upgrade_signals: ordered list of resources at ≥80% capacity.
    if (request.method === "GET" && url.pathname === "/api/account/usage") {
      const user = await requireAuth(request, env);
      if (!user) return json({ error: "Unauthorized" }, 401);
      try {
        const context = await getPlanContext(user, env);
        const percentages = {};
        for (const [key, used] of Object.entries(context.usage)) {
          const limit = context.limits[key];
          if (limit && limit < 999999 && typeof used === "number") {
            percentages[key] = Math.round((used / limit) * 100);
          }
        }
        const upgrade_signals = getUpgradeRecommendation(context.limits, context.usage);
        return json({ ...context, percentages, upgrade_signals });
      } catch (e) {
        return serverError("api", e);
      }
    }

    // ── GET /api/account/subscription/limits ─────────────────────────────
    // Backward-compatible alias for existing v1 screens.
    if (request.method === "GET" && url.pathname === "/api/account/subscription/limits") {
      const user = await requireAuth(request, env);
      if (!user) return json({ error: "Unauthorized" }, 401);
      try {
        const context = await getPlanContext(user, env);
        const entitlementUsage = await getEntitlementUsage(user, env);
        return json({
          plan: context.plan,
          limits: context.limits,
          usage: {
            ...context.usage,
            api_tokens: entitlementUsage.api_tokens,
            // These fields reflect plan limits (maximums), not usage counts.
            // Formerly misnamed: max_domains_in_workspace was set to usage.domains (wrong).
            domains_per_workspace_limit: context.limits.domains,
            scheduled_reports_per_workspace_limit: context.limits.scheduled_reports_per_workspace,
          },
        });
      } catch (e) {
        return serverError("api", e);
      }
    }

    // ── GET /api/admin/subscriptions ────────────────────────────────────
    if (request.method === "GET" && url.pathname === "/api/admin/subscriptions") {
      const user = await requireAuth(request, env);
      if (!user) return json({ error: "Unauthorized" }, 401);
      if (!(await isPlatformAdmin(user, env))) return json({ error: "Forbidden" }, 403);

      try {
        const rows = await env.cybermeters_db
          .prepare(
            `SELECT
               u.id AS user_id,
               u.email AS user_email,
               u.name AS user_name,
               cp.company_name,
               cp.contact_email,
               sa.plan,
               sa.subscription_status AS status,
               sa.created_at,
               sa.current_period_end AS expires_at
             FROM users u
             LEFT JOIN customer_profiles cp ON cp.owner_user_id = u.id
             LEFT JOIN subscriptions sa ON sa.owner_user_id = u.id
             ORDER BY COALESCE(sa.created_at, u.created_at) DESC
             LIMIT 500`
          )
          .all();

        return json({
          subscriptions: (rows.results || []).map((row) => ({
            customer: {
              user_id: row.user_id,
              email: row.user_email,
              name: row.user_name,
              company_name: row.company_name,
              contact_email: row.contact_email,
            },
            plan: normalizePlan(row.plan),
            status: row.status || "active",
            created_at: row.created_at,
            expires_at: row.expires_at,
          })),
        });
      } catch (e) {
        return serverError("api", e);
      }
    }

    // ── GET /api/account/api-tokens ─────────────────────────────────────
    if (request.method === "GET" && url.pathname === "/api/account/api-tokens") {
      const user = await requireAuth(request, env);
      if (!user) return json({ error: "Unauthorized" }, 401);
      // Token management is session-only — an API token cannot enumerate tokens.
      if (user.api_token_id) return json({ error: "Token management requires session authentication" }, 403);
      try {
        const rows = await env.cybermeters_db
          .prepare(
            `SELECT id, user_id, name, scope, workspace_id, last_used_at, created_at, expires_at, status
             FROM api_tokens
             WHERE user_id = ?
             ORDER BY created_at DESC`
          )
          .bind(user.id)
          .all();
        return json({ tokens: rows.results || [] });
      } catch (e) {
        return serverError("api", e);
      }
    }

    // ── POST /api/account/api-tokens ────────────────────────────────────
    if (request.method === "POST" && url.pathname === "/api/account/api-tokens") {
      const user = await requireAuth(request, env);
      if (!user) return json({ error: "Unauthorized" }, 401);
      if (user.api_token_id) return json({ error: "Token management requires session authentication" }, 403);

      let body;
      try { body = await request.json(); } catch { return json({ error: "Invalid JSON body" }, 400); }

      const name        = (body.name || "").trim();
      const scope       = (body.scope || "read").trim();
      const workspaceId = body.workspace_id ? String(body.workspace_id).trim() : null;
      const expiresAt   = body.expires_at   ? String(body.expires_at).trim()   : null;

      if (!name) return json({ error: "name is required" }, 400);
      if (name.length > 120) return json({ error: "name is too long" }, 400);
      if (!["read", "write", "admin"].includes(scope)) {
        return json({ error: "scope must be one of: read, write, admin" }, 400);
      }

      // If a workspace_id is provided, verify the user is a member of that workspace.
      if (workspaceId) {
        const wsAccess = await requireWorkspaceAccess(user, workspaceId, env);
        if (!wsAccess) return json({ error: "Workspace not found or access denied" }, 403);
      }

      try {
        // Entitlement: API token limit
        const plan = await getEffectivePlan(user.id, env);
        const tokUsage  = await getEntitlementUsage(user, env);
        const tokLimits = getPlanLimits(plan);
        if (tokUsage.api_tokens >= tokLimits.api_tokens) {
          return json(planLimitExceeded("api_tokens", tokLimits.api_tokens, tokUsage.api_tokens), 403);
        }

        const { raw, hash } = await generateApiToken();
        const tokenId = createId("apitok");
        await env.cybermeters_db
          .prepare(
            `INSERT INTO api_tokens
               (id, user_id, name, token_hash, scope, workspace_id, expires_at, status, created_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, 'active', datetime('now'))`
          )
          .bind(tokenId, user.id, name, hash, scope, workspaceId, expiresAt)
          .run();

        await createAuditEvent(env, {
          user_id:     user.id,
          event_type:  "api_token_created",
          entity_type: "api_token",
          entity_id:   tokenId,
          description: `API token "${name}" created (scope: ${scope})`,
          metadata:    { name, scope, workspace_id: workspaceId },
        });

        return json({ token: raw }, 201);
      } catch (e) {
        return serverError("api", e);
      }
    }

    // ── DELETE /api/account/api-tokens/:id ──────────────────────────────
    const apiTokenDeleteMatch = url.pathname.match(/^\/api\/account\/api-tokens\/([^/]+)$/);
    if (apiTokenDeleteMatch && request.method === "DELETE") {
      const user = await requireAuth(request, env);
      if (!user) return json({ error: "Unauthorized" }, 401);
      if (user.api_token_id) return json({ error: "Token management requires session authentication" }, 403);
      const tokenId = apiTokenDeleteMatch[1];

      try {
        const tokenRow = await env.cybermeters_db
          .prepare("SELECT id, name FROM api_tokens WHERE id = ? AND user_id = ?")
          .bind(tokenId, user.id)
          .first();
        if (!tokenRow) return json({ error: "Token not found" }, 404);

        const result = await env.cybermeters_db
          .prepare("UPDATE api_tokens SET status = 'revoked' WHERE id = ? AND user_id = ?")
          .bind(tokenId, user.id)
          .run();
        if (result.meta?.changes === 0) return json({ error: "Token not found" }, 404);

        await createAuditEvent(env, {
          user_id:     user.id,
          event_type:  "api_token_revoked",
          entity_type: "api_token",
          entity_id:   tokenId,
          description: `API token "${tokenRow.name}" revoked`,
          metadata:    { name: tokenRow.name },
        });

        return json({ success: true });
      } catch (e) {
        return serverError("api", e);
      }
    }

    // ── GET /api/account/login-history ──────────────────────────────────
    // Returns recent auth-related audit events for the authenticated user.
    // Reuses audit_events — no duplicate storage.
    // Tenant/user isolation: WHERE user_id = ? enforced.
    if (request.method === "GET" && url.pathname === "/api/account/login-history") {
      const user = await requireAuth(request, env);
      if (!user) return json({ error: "Unauthorized" }, 401);
      // API tokens may not access personal security history
      if (user.api_token_id) return json({ error: "Session authentication required" }, 403);

      const HISTORY_TYPES = [
        "login", "USER_LOGIN_MICROSOFT", "login_failed",
        "mfa_challenge_success", "mfa_challenge_failed",
        "recovery_code_used",
        "password_reset_completed", "password_reset_failed",
      ];
      const SUCCESS_TYPES = new Set(["login", "USER_LOGIN_MICROSOFT", "mfa_challenge_success", "recovery_code_used", "password_reset_completed"]);

      try {
        const rows = await env.cybermeters_db
          .prepare(
            `SELECT id, event_type, description, metadata_json, created_at
             FROM audit_events
             WHERE user_id = ?
               AND event_type IN (${HISTORY_TYPES.map(() => "?").join(",")})
             ORDER BY created_at DESC
             LIMIT 100`
          )
          .bind(user.id, ...HISTORY_TYPES)
          .all();

        const events = (rows.results || []).map(row => {
          let meta = {};
          try { meta = row.metadata_json ? JSON.parse(row.metadata_json) : {}; } catch { /* ignore */ }
          return {
            id:          row.id,
            timestamp:   row.created_at,
            event_type:  row.event_type,
            ip_address:  meta.ip_address || null,
            user_agent:  meta.user_agent || null,
            result:      SUCCESS_TYPES.has(row.event_type) ? "success" : "failed",
            description: row.description || null,
          };
        });

        createAuditEvent(env, {
          user_id:     user.id,
          event_type:  "login_history_viewed",
          entity_type: "user",
          entity_id:   user.id,
          description: "User viewed their login history",
        }).catch(() => {});

        return json({ events });
      } catch (e) {
        return serverError("api", e);
      }
    }

    // ── GET /api/account/sessions ────────────────────────────────────────
    // Returns active (non-expired) sessions for the authenticated user.
    // Marks current session; never exposes token_hash.
    // Tenant/user isolation: WHERE user_id = ? enforced.
    if (request.method === "GET" && url.pathname === "/api/account/sessions") {
      const user = await requireAuth(request, env);
      if (!user) return json({ error: "Unauthorized" }, 401);
      if (user.api_token_id) return json({ error: "Session authentication required" }, 403);

      try {
        // Identify current session by hashing the bearer token from this request
        const _authRaw = (request.headers.get("Authorization") || "").slice(7).trim();
        const _currentHash = _authRaw ? await hashToken(_authRaw) : null;

        const rows = await env.cybermeters_db
          .prepare(
            `SELECT id, created_at, last_seen_at, ip_address, user_agent, token_hash, expires_at
             FROM user_sessions
             WHERE user_id = ? AND expires_at > datetime('now')
             ORDER BY created_at DESC`
          )
          .bind(user.id)
          .all();

        const sessions = (rows.results || []).map(s => ({
          session_id:  s.id,
          created_at:  s.created_at,
          last_seen_at: s.last_seen_at || null,
          expires_at:  s.expires_at,
          ip_address:  s.ip_address  || null,
          user_agent:  s.user_agent  || null,
          current:     _currentHash !== null && s.token_hash === _currentHash,
          // token_hash intentionally excluded from response
        }));

        createAuditEvent(env, {
          user_id:     user.id,
          event_type:  "active_sessions_viewed",
          entity_type: "user",
          entity_id:   user.id,
          description: "User viewed their active sessions",
        }).catch(() => {});

        return json({ sessions });
      } catch (e) {
        return serverError("api", e);
      }
    }

    // ── POST /api/account/sessions/:id/revoke ───────────────────────────
    // Revoke a specific session. Cannot revoke the current session via this
    // endpoint — use POST /api/auth/logout for self-termination.
    // Tenant/user isolation: WHERE user_id = ? enforced.
    const sessionRevokeMatch = url.pathname.match(/^\/api\/account\/sessions\/([^/]+)\/revoke$/);
	    if (sessionRevokeMatch && request.method === "POST") {
	      const user = await requireAuth(request, env);
	      if (!user) return json({ error: "Unauthorized" }, 401);
	      if (user.api_token_id) return json({ error: "Session authentication required" }, 403);
      const targetSessionId = sessionRevokeMatch[1];

      try {
        // Verify the session belongs to this user (isolation enforced by AND user_id = ?)
        const target = await env.cybermeters_db
          .prepare("SELECT id, token_hash FROM user_sessions WHERE id = ? AND user_id = ? LIMIT 1")
          .bind(targetSessionId, user.id)
          .first();
        if (!target) return json({ error: "Session not found" }, 404);

        // Prevent accidental current-session revocation — use /api/auth/logout instead
        const _authRaw = (request.headers.get("Authorization") || "").slice(7).trim();
        if (_authRaw) {
          const _currentHash = await hashToken(_authRaw);
          if (target.token_hash === _currentHash) {
            return json({ error: "Use Sign Out to end your current session." }, 400);
          }
        }

        await env.cybermeters_db
          .prepare("DELETE FROM user_sessions WHERE id = ? AND user_id = ?")
          .bind(targetSessionId, user.id)
          .run();

        await createAuditEvent(env, {
          user_id:     user.id,
          event_type:  "session_revoked",
          entity_type: "user",
          entity_id:   user.id,
          description: "User revoked an active session",
          metadata:    { revoked_session_id: targetSessionId },
        }).catch(() => {});

        return json({ success: true, message: "Session revoked." });
      } catch (e) {
	        return serverError("api", e);
	      }
	    }

	    // ── GET /api/account/export ─────────────────────────────────────────
	    // GDPR-ready personal data export. Session auth only; explicit columns
	    // avoid secrets such as passwords, MFA material, token hashes, and invite tokens.
	    if (request.method === "GET" && url.pathname === "/api/account/export") {
	      const user = await requireAuth(request, env);
	      if (!user) return json({ error: "Unauthorized" }, 401);
	      if (user.api_token_id) return json({ error: "Session authentication required" }, 403);
	      try {
	        const email = String(user.email || "").trim().toLowerCase();
	        const [profile, workspaces, loginHistory, sessions, auditEvents, invitations] = await Promise.all([
	          env.cybermeters_db
	            .prepare("SELECT id, email, name, plan, status, created_at FROM users WHERE id = ?")
	            .bind(user.id)
	            .first(),
	          env.cybermeters_db
	            .prepare(
	              `SELECT w.id, w.name, w.created_at, wm.role,
	                      CASE WHEN w.owner_user_id = ? THEN 1 ELSE 0 END AS owned
	               FROM workspaces w
	               LEFT JOIN workspace_members wm ON wm.workspace_id = w.id AND wm.user_id = ?
	               WHERE wm.user_id IS NOT NULL
	                  OR (w.owner_user_id = ? AND NOT EXISTS (
	                    SELECT 1 FROM workspace_members any_wm WHERE any_wm.workspace_id = w.id
	                  ))
	               ORDER BY w.created_at DESC`
	            )
	            .bind(user.id, user.id, user.id)
	            .all(),
	          env.cybermeters_db
	            .prepare(
	              `SELECT id, event_type, description, metadata_json, created_at
	               FROM audit_events
	               WHERE user_id = ?
	                 AND event_type IN ('login', 'login_failed', 'mfa_challenge_success',
	                                    'mfa_challenge_failed', 'recovery_code_used',
	                                    'password_reset_completed', 'password_reset_failed')
	               ORDER BY created_at DESC
	               LIMIT 250`
	            )
	            .bind(user.id)
	            .all(),
	          env.cybermeters_db
	            .prepare(
	              `SELECT id, created_at, last_seen_at, ip_address, user_agent, expires_at
	               FROM user_sessions
	               WHERE user_id = ?
	               ORDER BY created_at DESC
	               LIMIT 250`
	            )
	            .bind(user.id)
	            .all(),
	          env.cybermeters_db
	            .prepare(
	              `SELECT id, workspace_id, event_type, entity_type, entity_id,
	                      description, metadata_json, created_at
	               FROM audit_events
	               WHERE user_id = ?
	               ORDER BY created_at DESC
	               LIMIT 500`
	            )
	            .bind(user.id)
	            .all(),
	          env.cybermeters_db
	            .prepare(
	              `SELECT id, workspace_id, email, role, invited_by, status,
	                      expires_at, accepted_at, created_at
	               FROM workspace_invitations
	               WHERE email = ?
	               ORDER BY created_at DESC
	               LIMIT 250`
	            )
	            .bind(email)
	            .all(),
	        ]);

	        await createAuditEvent(env, {
	          user_id: user.id,
	          event_type: "account_export_requested",
	          entity_type: "user",
	          entity_id: user.id,
	          description: "Account data export requested",
	        }).catch(() => {});

	        return json({
	          exported_at: new Date().toISOString(),
	          user_profile: profile || { id: user.id, email: user.email, name: user.name || null },
	          workspaces: workspaces.results || [],
	          login_history: loginHistory.results || [],
	          sessions: sessions.results || [],
	          audit_events: auditEvents.results || [],
	          invitations: invitations.results || [],
	          excluded: ["password_hash", "totp_secret", "mfa_recovery_codes_hash_json", "session_token_hashes", "api_token_hashes", "invitation_token_hashes", "workspace_scan_data", "reports"],
	        });
	      } catch {
	        return json({ error: "Unable to export account data" }, 500);
	      }
	    }

	    // ── POST /api/account/delete-request ────────────────────────────────
	    if (request.method === "POST" && url.pathname === "/api/account/delete-request") {
	      const user = await requireAuth(request, env);
	      if (!user) return json({ error: "Unauthorized" }, 401);
	      if (user.api_token_id) return json({ error: "Session authentication required" }, 403);
	      try {
	        const existing = await env.cybermeters_db
	          .prepare("SELECT id, created_at FROM deletion_requests WHERE request_type = 'account' AND user_id = ? AND status = 'pending' LIMIT 1")
	          .bind(user.id)
	          .first();
	        if (existing) return json({ request_id: existing.id, status: "pending", created_at: existing.created_at, message: "Account deletion request already exists." });

	        const requestId = createId("delreq");
	        const now = new Date().toISOString();
	        await env.cybermeters_db
	          .prepare(
	            `INSERT INTO deletion_requests
	               (id, request_type, user_id, requested_by, status, created_at, updated_at)
	             VALUES (?, 'account', ?, ?, 'pending', ?, ?)`
	          )
	          .bind(requestId, user.id, user.id, now, now)
	          .run();
	        await createAuditEvent(env, {
	          user_id: user.id,
	          event_type: "account_deletion_requested",
	          entity_type: "user",
	          entity_id: user.id,
	          description: "Account deletion requested",
	          metadata: { request_id: requestId },
	        }).catch(() => {});
	        return json({ request_id: requestId, status: "pending", message: "Account deletion request received." }, 202);
	      } catch {
	        return json({ error: "Unable to create deletion request" }, 500);
	      }
	    }
	
	    // ── GET /api/platform/accuracy ───────────────────────────────────────
	    if (request.method === "GET" && url.pathname === "/api/platform/accuracy") {
      const user = await requireAuth(request, env);
      if (!user) return json({ error: "Unauthorized" }, 401);

      try {
        const workspaceIds = await getAccessibleWorkspaceIds(user, env);
        const regression = evaluateRegressionFixtures();

        if (workspaceIds.length === 0) {
          return json({
            accuracy_score:              0,
            findings_total:              0,
            high_confidence_pct:         0,
            low_confidence_pct:          0,
            evidence_complete_pct:       0,
            validation_uncertain_count:  0,
            validation_uncertain_pct:    0,
            resolver_agreement_avg:      null,
            header_validation_score:     75,
            golden_domain_coverage:      Math.min(100, Math.round(((regression.total ?? 0) / 15) * 100)),
            regression_pass_rate:        regression.pass_rate,
            regression_fixture_count:    regression.total ?? 0,
          });
        }

        const placeholders = workspaceIds.map(() => "?").join(",");
        const rows = await env.cybermeters_db
          .prepare(
            `SELECT DISTINCT f.id, f.title, f.confidence, f.evidence_json
             FROM findings f
             JOIN scans s ON s.id = f.scan_id
             LEFT JOIN workspace_domains wd ON wd.domain_id = s.domain_id
             WHERE s.workspace_id IN (${placeholders})
                OR (s.workspace_id IS NULL AND wd.workspace_id IN (${placeholders}))`
          )
          .bind(...workspaceIds, ...workspaceIds)
          .all();

        const findings = rows.results || [];
        const total = findings.length;
        let high = 0;
        let low = 0;
        let complete = 0;
        let uncertain = 0;

        for (const row of findings) {
          const confidence = String(row.confidence || "").toLowerCase();
          if (confidence === "high") high += 1;
          if (confidence === "low") low += 1;

          let evidence = null;
          try { evidence = row.evidence_json ? JSON.parse(row.evidence_json) : null; } catch {}
          const quality = validateFindingEvidence({
            title: row.title,
            confidence: row.confidence,
            score_impact: 0,
            evidence,
          }).evidence_quality;
          if (quality === "excellent" || quality === "good") complete += 1;

          const evidenceText = JSON.stringify(evidence || {}).toLowerCase();
          if (
            /validation uncertain/i.test(row.title || "")
            || confidence === "low"
            || evidenceText.includes("validation_uncertain")
          ) {
            uncertain += 1;
          }
        }

        const pct = (n) => total > 0 ? Math.round((n / total) * 100) : 0;

        // Compute resolver_agreement_avg from findings that have the field in evidence
        let raTotal = 0, raCount = 0;
        for (const row of findings) {
          let evidence = null;
          try { evidence = row.evidence_json ? JSON.parse(row.evidence_json) : null; } catch {}
          if (evidence?.resolver_agreement_score != null) {
            raTotal += evidence.resolver_agreement_score;
            raCount += 1;
          }
        }
        const resolverAgreementAvg = raCount > 0 ? Math.round(raTotal / raCount) : null;

        // header_validation_score: % of findings with header evidence where strength is "valid"
        // (proxy for how well the scanner can classify header quality)
        let hvValid = 0, hvTotal = 0;
        for (const row of findings) {
          let evidence = null;
          try { evidence = row.evidence_json ? JSON.parse(row.evidence_json) : null; } catch {}
          if (evidence?.evidence_type === "http_header_probe") {
            hvTotal += 1;
            const sc = String(evidence?.strength_classification || "");
            if (sc === "valid" || sc === "") hvValid += 1;  // absent = not weak
          }
        }
        const headerValidationScore = hvTotal > 0 ? Math.round((hvValid / hvTotal) * 100) : 75; // default 75 — no header data yet

        // golden_domain_coverage: fixture count / 15 (target fixture count for v5)
        // golden_domain_coverage: regression.total / 15 (v5 fixture target)
        const goldenDomainCoverage = Math.min(100, Math.round(((regression.total ?? 0) / 15) * 100));

        // accuracy_score formula (v5):
        //   35% resolver_agreement_avg      — cross-resolver consistency
        //   25% header_validation_score     — header strength classification accuracy
        //   20% evidence_complete_pct       — finding evidence completeness
        //   10% regression_pass_rate        — regression fixture coverage
        //   10% golden_domain_coverage      — golden domain fixture breadth (15 fixture target)
        const evidenceCompletePct    = pct(complete);
        const highConfidencePct      = pct(high);
        const regressionPassRate     = regression.pass_rate;
        const validationUncertainPct = pct(uncertain);
        const resolverAvgForScore    = resolverAgreementAvg ?? 50;

        const accuracyScore = Math.round(
          resolverAvgForScore    * 0.35
          + headerValidationScore  * 0.25
          + evidenceCompletePct    * 0.20
          + regressionPassRate     * 0.10
          + goldenDomainCoverage   * 0.10
        );

        return json({
          accuracy_score:              accuracyScore,
          findings_total:              total,
          high_confidence_pct:         highConfidencePct,
          low_confidence_pct:          pct(low),
          evidence_complete_pct:       evidenceCompletePct,
          validation_uncertain_count:  uncertain,
          validation_uncertain_pct:    validationUncertainPct,
          resolver_agreement_avg:      resolverAgreementAvg,
          header_validation_score:     headerValidationScore,
          golden_domain_coverage:      goldenDomainCoverage,
          regression_pass_rate:        regressionPassRate,
          regression_fixture_count:    regression.total ?? 0,
        });
      } catch (e) {
        return serverError("api", e);
      }
    }


  return null;
}
