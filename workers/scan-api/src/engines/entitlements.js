// ── Subscription entitlements ──
// Plan limits/features/metadata tables, plan normalisation, payment grace-period state, and
// user/effective plan resolution + feature entitlement checks. Extracted verbatim from
// index.js (monolith decomposition, Phase 1c). isExpiredDate + PAYMENT_GRACE_PERIOD_DAYS internal.
// Prices and domain limits derive from the canonical pricing registry
// (pricing-registry.js ← docs/PRICING-POLICY.md, locked 2026-07-19). Do not
// hand-edit a price or domain count here.
import { CANONICAL_PLANS, TRIAL_SPEC, penceToGbp } from "./pricing-registry.js";

// ── Subscription Entitlements ────────────────────────────────────────────────

export const PLAN_LIMITS = {
  free: {
    // `free` is the post-trial / no-subscription state. Policy §4: monitoring
    // stops at trial expiry (fail-closed); prior evidence stays readable.
    // Zero new scans/reports/schedules — read-only access to existing history.
    workspaces: 1,
    domains: CANONICAL_PLANS.free.included_domains,
    users: 1,
    history_days: 30,
    report_retention: "90_days",
    api_tokens: 1,
    scheduled_reports_per_workspace: 0,
    scans_per_month: 0,
    scan_starts_per_hour: 0,
    reports_per_month: 0,
    scheduled_scans: 0,
    pending_invitations: 0,
  },
  starter: {
    workspaces: 1,  // SMB = single tenant; domains are the value metric (see pricing cards)
    domains: CANONICAL_PLANS.starter.included_domains,
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
    workspaces: 1,  // SMB = single tenant; 3 domains in one workspace (see pricing cards)
    domains: CANONICAL_PLANS.professional.included_domains,
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
    // Base plan INCLUDES 10 domains. Domains 11–25 exist in the canonical
    // policy as per-domain overage (+£3/mo, hard cap 25) but per-domain overage
    // BILLING is not yet wired to Stripe, so entitlement fails closed at the
    // included count — a domain we cannot bill is a domain we do not grant.
    // See domainLimitRejection (plan-usage.js) for the honest customer copy.
    domains: CANONICAL_PLANS.business.included_domains,
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

// Derived verbatim from the canonical pricing registry. The legacy shape
// (name/description/monthly_gbp/annual_gbp/annual_equivalent_monthly_gbp/
// checkout_enabled) is preserved for existing consumers; the additive
// `pricing_model` block carries the per-domain commercial model (Business
// overage, MSP base + metered domains) so no surface has to invent it.
function buildBillingPlanMetadata() {
  const out = {};
  for (const [key, p] of Object.entries(CANONICAL_PLANS)) {
    const annualGbp = penceToGbp(p.annual_pence);
    out[key] = {
      name: p.name,
      description: p.description,
      monthly_gbp: penceToGbp(p.monthly_pence),
      annual_gbp: annualGbp,
      annual_equivalent_monthly_gbp: annualGbp === null
        ? null
        : Math.round(p.annual_pence / 12) / 100,
      checkout_enabled: p.checkout_enabled === true,
      pricing_model: {
        currency: "gbp",
        included_domains: p.included_domains,
        ...(p.additional_domain_monthly_pence ? {
          additional_domain_monthly_gbp: penceToGbp(p.additional_domain_monthly_pence),
          additional_domain_annual_gbp: penceToGbp(p.additional_domain_annual_pence),
          domain_hard_cap: p.domain_hard_cap,
        } : {}),
        ...(p.base_monthly_pence ? {
          base_monthly_gbp: penceToGbp(p.base_monthly_pence),
          base_annual_gbp: penceToGbp(p.base_annual_pence),
          per_domain_monthly_gbp: penceToGbp(p.per_domain_monthly_pence),
          per_domain_annual_gbp: penceToGbp(p.per_domain_annual_pence),
          min_billed_domains: p.min_billed_domains,
          floor_monthly_gbp: penceToGbp(p.floor_monthly_pence),
          floor_annual_gbp: penceToGbp(p.floor_annual_pence),
        } : {}),
        ...(key === "free" ? {
          trial: {
            duration_days: TRIAL_SPEC.duration_days,
            domains: TRIAL_SPEC.domains,
            card_required: TRIAL_SPEC.card_required,
          },
        } : {}),
      },
    };
  }
  return out;
}

export const BILLING_PLAN_METADATA = buildBillingPlanMetadata();

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

// isTrialWindowValid — a `trialing` row is entitled only while its trial
// window genuinely runs. The window end is trial_end, falling back to
// current_period_end for Stripe-managed trials that carry no local trial
// columns. A trialing row with NEITHER end date fails CLOSED: before this
// rule, locally-provisioned trials (trial_end set, current_period_end NULL)
// passed the old current_period_end-only check forever — a 14-day trial that
// never expired at runtime.
function isTrialWindowValid(sub) {
  const end = sub?.trial_end || sub?.current_period_end || null;
  if (!end) return false;
  const t = new Date(end).getTime();
  if (Number.isNaN(t)) return false;
  return t > Date.now();
}

// resolveCanonicalSubscriptionRow — the ONE decision for which subscription
// row governs an owner's entitlement when history holds several (append-only
// billing rows are never deleted). Explicit precedence, never newest-row
// ordering (F0 precondition, ROADMAP-TO-FIRST-PAYING-CUSTOMER.md):
//   0. lineage supersession — rows sharing a billing lineage (same
//      stripe_subscription_id, or same workspace_id) are the SAME
//      subscription's history: only the newest row of a lineage stands, so a
//      cancellation can never be out-shadowed by its own stale predecessor.
//   1. an unexpired ACTIVE paid row — the purchased reality. A customer
//      receives exactly what they pay for, so a live paid plan beats a
//      concurrent trial row in either direction.
//   2. a trialing row inside a valid trial window.
//   3. a past_due row inside the 7-day payment grace window.
// Within a class: Stripe-bound rows (stripe_subscription_id) beat local rows,
// then latest updated_at/created_at, then id — fully deterministic.
// Returns { row, source: "paid" | "trial" | "grace" } or null (→ free).
export function resolveCanonicalSubscriptionRow(rows) {
  const all = Array.isArray(rows) ? rows.filter(Boolean) : [];
  const recency = (r) => String(r.updated_at || r.created_at || "");
  const newer = (a, b) => {
    const aT = recency(a), bT = recency(b);
    if (aT !== bT) return aT > bT;
    return String(a.id || "") > String(b.id || "");
  };
  const sameLineage = (a, b) =>
    (a.stripe_subscription_id && a.stripe_subscription_id === b.stripe_subscription_id) ||
    (a.workspace_id && a.workspace_id === b.workspace_id);
  const list = all.filter((r) => !all.some((o) => o !== r && sameLineage(r, o) && newer(o, r)));
  const statusOf = (r) => String(r.subscription_status || r.status || "").trim().toLowerCase();
  const activePaid = list.filter((r) => statusOf(r) === "active" && !isExpiredDate(r.current_period_end ?? r.expires_at ?? null));
  const trialing = list.filter((r) => statusOf(r) === "trialing" && isTrialWindowValid(r));
  const grace = list.filter((r) => statusOf(r) === "past_due" && getPaymentGraceState(r).active);
  const pickDeterministic = (candidates) => {
    const sorted = [...candidates].sort((a, b) => {
      const aStripe = a.stripe_subscription_id ? 1 : 0;
      const bStripe = b.stripe_subscription_id ? 1 : 0;
      if (aStripe !== bStripe) return bStripe - aStripe;
      const aT = recency(a), bT = recency(b);
      if (aT !== bT) return aT < bT ? 1 : -1;
      return String(a.id || "") < String(b.id || "") ? 1 : -1;
    });
    return sorted[0] ?? null;
  };
  if (activePaid.length) return { row: pickDeterministic(activePaid), source: "paid" };
  if (trialing.length) return { row: pickDeterministic(trialing), source: "trial" };
  if (grace.length) return { row: pickDeterministic(grace), source: "grace" };
  return null;
}

export async function getEffectivePlanState(userId, env) {
  // Canonical plan resolver for all application billing decisions.
  // Stripe updates the subscriptions table through webhooks; runtime requests
  // must continue to read through this helper rather than Stripe.
  //
  // Behavior:
  // - missing user_id, no entitling row, D1 errors -> { plan: "free" }
  // - active paid row (unexpired) -> its plan
  // - trialing row inside a valid trial window -> its plan, is_trial: true
  //   (trial window = trial_end, else current_period_end; neither -> free)
  // - past_due inside the 7-day payment grace window -> keep the paid plan
  // - duplicate rows resolve by resolveCanonicalSubscriptionRow, never by
  //   ambiguous newest-row ordering
  if (!userId) return { plan: "free", is_trial: false, source: "none" };
  try {
    const res = await env.cybermeters_db
      .prepare(
        `SELECT id, workspace_id, plan, status, subscription_status, trial_end,
                expires_at, current_period_end, payment_failed_at,
                stripe_subscription_id, created_at, updated_at
         FROM subscriptions
         WHERE owner_user_id = ?`
      )
      .bind(userId)
      .all();
    const resolved = resolveCanonicalSubscriptionRow(res?.results || []);
    if (!resolved) return { plan: "free", is_trial: false, source: "none" };
    return {
      plan: normalizePlan(resolved.row.plan),
      is_trial: resolved.source === "trial",
      source: resolved.source,
    };
  } catch {
    return { plan: "free", is_trial: false, source: "none" };
  }
}

export async function getUserPlan(userId, env) {
  return (await getEffectivePlanState(userId, env)).plan;
}

export async function getEffectivePlan(userId, env) {
  return getUserPlan(userId, env);
}

// Trial domain cap (policy §4): the 14-Day Full Trial grants the full product
// but exactly ONE monitored domain, regardless of the feature plan it borrows.
export function getEffectiveDomainLimit(plan, isTrial) {
  if (isTrial) return TRIAL_SPEC.domains;
  const normalized = normalizePlan(plan);
  return (PLAN_LIMITS[normalized] ?? PLAN_LIMITS.free).domains;
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
