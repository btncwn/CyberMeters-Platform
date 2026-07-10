// ── Subscription entitlements ──
// Plan limits/features/metadata tables, plan normalisation, payment grace-period state, and
// user/effective plan resolution + feature entitlement checks. Extracted verbatim from
// index.js (monolith decomposition, Phase 1c). isExpiredDate + PAYMENT_GRACE_PERIOD_DAYS internal.

// ── Subscription Entitlements ────────────────────────────────────────────────

export const PLAN_LIMITS = {
  free: {
    workspaces: 1,
    domains: 1,       // UK Cyber MOT tiers (2026-07): Free 1 / Starter 1 / Pro 5 / Business 20 / MSP(enterprise) 20-100+
    users: 1,
    history_days: 30,
    report_retention: "90_days",
    api_tokens: 1,
    scheduled_reports_per_workspace: 1,
    scans_per_month: 5,
    scan_starts_per_hour: 5,
    reports_per_month: 3,
    scheduled_scans: 0,       // free plan: no scheduled scans
    pending_invitations: 10,
  },
  starter: {
    workspaces: 1,  // SMB = single tenant; domains are the value metric (see pricing cards)
    domains: 1,
    users: 3,
    history_days: 90,
    report_retention: "90_days",
    api_tokens: 5,
    scheduled_reports_per_workspace: 3,
    scans_per_month: 100,
    scan_starts_per_hour: 20,
    reports_per_month: 50,
    scheduled_scans: 5,
    pending_invitations: 25,
  },
  professional: {
    workspaces: 1,  // SMB = single tenant; 5 domains in one workspace (see pricing cards)
    domains: 5,
    users: 10,
    history_days: 365,
    report_retention: "2_years",
    api_tokens: 25,
    scheduled_reports_per_workspace: 10,
    scans_per_month: 1000,
    scan_starts_per_hour: 100,
    reports_per_month: 500,
    scheduled_scans: 20,
    pending_invitations: 50,
  },
  business: {
    workspaces: 50,
    domains: 20,
    users: 50,
    history_days: 730,
    report_retention: "7_years",
    api_tokens: 100,
    scheduled_reports_per_workspace: 50,
    scans_per_month: 5000,
    scan_starts_per_hour: 300,
    reports_per_month: 2000,
    scheduled_scans: 100,
    pending_invitations: 250,
  },
  enterprise: {
    workspaces: 999999,
    domains: 999999,
    users: 999999,
    history_days: 999999,
    report_retention: "forever",
    api_tokens: 999999,
    scheduled_reports_per_workspace: 999999,
    scans_per_month: 999999,
    scan_starts_per_hour: 999999,
    reports_per_month: 999999,
    scheduled_scans: 999999,
    pending_invitations: 999999,
  },
};

export const PLAN_FEATURES = {
  free: [],
  starter: [
    // ── Sprint 14 gates ───────────────────────────────────────────────────
    "scheduled_scans",    // can create scheduled scans
    "alerts",             // email + in-app alert notifications
    "pdf_reports",        // PDF report generation and download
    "multi_workspace",    // can create more than 1 workspace
    "team_members",       // can invite workspace members
    // ── Pre-existing gates ────────────────────────────────────────────────
    "business_risk_score",
  ],
  professional: [
    "scheduled_scans",
    "alerts",
    "pdf_reports",
    "multi_workspace",
    "team_members",
    "business_risk_score",
    "cyber_essentials",
    "vendor_risk",
    "executive_dashboard",  // Executive Risk Dashboard: professional+
    "audit_logs",           // Workspace audit trail: professional+
  ],
  business: [
    "scheduled_scans",
    "alerts",
    "pdf_reports",
    "multi_workspace",
    "team_members",
    "business_risk_score",
    "cyber_essentials",
    "vendor_risk",
    "executive_dashboard",
    "audit_logs",
    "portfolio_monitoring",
    "white_label",
  ],
  enterprise: [
    "scheduled_scans",
    "alerts",
    "pdf_reports",
    "multi_workspace",
    "team_members",
    "business_risk_score",
    "cyber_essentials",
    "vendor_risk",
    "executive_dashboard",
    "audit_logs",
    "portfolio_monitoring",
    "white_label",
    "msp_dashboard",
  ],
};

export const BILLING_PLAN_METADATA = {
  free: {
    name: "Free",
    description: "Platform evaluation with basic scans and on-screen results.",
    monthly_gbp: 0,
    annual_gbp: 0,
    annual_equivalent_monthly_gbp: 0,
    checkout_enabled: false,
  },
  starter: {
    name: "Starter",
    description: "Business Risk Score, scheduled scans, and basic executive reports.",
    monthly_gbp: 29,
    annual_gbp: 276,
    annual_equivalent_monthly_gbp: 23,
    checkout_enabled: true,
  },
  professional: {
    name: "Professional",
    description: "Cyber Essentials Readiness, Vendor Risk, and advanced reports.",
    monthly_gbp: 149,
    annual_gbp: 1428,
    annual_equivalent_monthly_gbp: 119,
    checkout_enabled: true,
  },
  business: {
    name: "Business",
    description: "Portfolio Monitoring, White Label reports, and extended retention.",
    monthly_gbp: 399,
    annual_gbp: 3828,
    annual_equivalent_monthly_gbp: 319,
    checkout_enabled: true,
  },
  enterprise: {
    name: "Enterprise",
    description: "MSP Dashboard, custom limits, priority support, and dedicated onboarding.",
    monthly_gbp: null,
    annual_gbp: null,
    annual_equivalent_monthly_gbp: null,
    checkout_enabled: false,
  },
};

export function normalizePlan(plan) {
  const value = String(plan || "free").trim().toLowerCase();
  return Object.prototype.hasOwnProperty.call(PLAN_LIMITS, value) ? value : "free";
}

function isExpiredDate(value) {
  if (!value) return false;
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? false : date.getTime() <= Date.now();
}

// Payment-failure grace window: paid access continues while Stripe retries
// collection. Shared by runtime plan resolution (getUserPlan) AND the billing
// UI endpoint so entitlements and the customer-facing plan state can never
// disagree during the grace period.
const PAYMENT_GRACE_PERIOD_DAYS = 7;

export function getPaymentGraceState(sub) {
  const status = String(sub?.subscription_status || "").trim().toLowerCase();
  if (status !== "past_due") return { active: false, ends_at: null };
  const failedAt = sub?.payment_failed_at ? new Date(sub.payment_failed_at).getTime() : 0;
  if (!failedAt || Number.isNaN(failedAt)) return { active: false, ends_at: null };
  const endsAtMs = failedAt + PAYMENT_GRACE_PERIOD_DAYS * 24 * 60 * 60 * 1000;
  return { active: Date.now() < endsAtMs, ends_at: new Date(endsAtMs).toISOString() };
}

export async function getUserPlan(userId, env) {
  // Canonical plan resolver for all application billing decisions.
  // Stripe updates the subscriptions table through webhooks; runtime requests
  // must continue to read through this helper rather than Stripe.
  //
  // Current behavior:
  // - missing user_id, missing subscription row, D1 errors -> free
  // - non-active subscription_status values -> free
  // - past_due inside the payment grace window -> keep the paid plan
  // - expired current_period_end -> free
  // - otherwise normalize and return subscriptions.plan
  if (!userId) return "free";
  try {
    const sub = await env.cybermeters_db
      .prepare(
        `SELECT plan, subscription_status, current_period_end, payment_failed_at
         FROM subscriptions
         WHERE owner_user_id = ?
         ORDER BY COALESCE(updated_at, created_at) DESC
         LIMIT 1`
      )
      .bind(userId)
      .first();

    if (!sub) return "free";
    const status = String(sub.subscription_status || "").trim().toLowerCase();
    if (status === "past_due") {
      return getPaymentGraceState(sub).active ? normalizePlan(sub.plan) : "free";
    }
    if (status && !["active", "trialing"].includes(status)) return "free";
    if (isExpiredDate(sub.current_period_end)) return "free";
    return normalizePlan(sub.plan);
  } catch {
    return "free";
  }
}

export async function getEffectivePlan(userId, env) {
  return getUserPlan(userId, env);
}

export function getPlanFeatures(plan) {
  const normalized = normalizePlan(plan);
  return [...(PLAN_FEATURES[normalized] ?? PLAN_FEATURES.free)];
}

export function hasFeatureEntitlement(plan, featureKey) {
  if (!featureKey || typeof featureKey !== "string") return false;
  return getPlanFeatures(plan).includes(featureKey);
}

// Billing interval normaliser (monthly|annual).
export function normalizeBillingInterval(interval) {
  const value = String(interval || "monthly").trim().toLowerCase();
  return (value === "annual" || value === "yearly") ? "annual" : "monthly";
}
