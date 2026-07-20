// ── Canonical pricing registry ──
// Machine-readable mirror of docs/PRICING-POLICY.md (CANONICAL · FOUNDER-FINAL ·
// LOCKED 2026-07-19). That document is the single pricing authority; this module
// is its one runtime projection. Any price/tier/limit change MUST update the
// policy document first, then this registry, Stripe prices and the pricing
// cards in one founder-approved lockstep (policy §7). No other module may carry
// an independent price, domain-limit or trial figure.
//
// All money values are integer pence (GBP). Display values are derived — never
// hand-write a second copy of a price. Annual = exactly 10 × monthly (policy §3:
// exact figures, never a recomputed percentage).

export const PRICING_POLICY_VERSION = "2026-07-19";

// Internal plan keys are unchanged (policy §5): free / starter / professional /
// business / enterprise. `free` is the 14-Day Full Trial (time-limited, then
// fail-closed read-only); `enterprise` is the MSP plan (distinct customer type,
// sales-led — not self-serve checkout).
export const CANONICAL_PLANS = {
  free: {
    key: "free",
    name: "14-Day Full Trial",
    description:
      "Full Cyber MOT for 14 days — all 8 categories, alerts, cases, reports and remediation. 1 monitored domain. No card required.",
    monthly_pence: 0,
    annual_pence: 0,
    included_domains: 1,
    checkout_enabled: false,
  },
  starter: {
    key: "starter",
    name: "Starter",
    description: "Full Cyber MOT for 1 monitored domain.",
    monthly_pence: 999,
    annual_pence: 9990,
    included_domains: 1,
    checkout_enabled: true,
  },
  professional: {
    key: "professional",
    name: "Professional",
    description: "Full Cyber MOT for up to 3 monitored domains.",
    monthly_pence: 1999,
    annual_pence: 19990,
    included_domains: 3,
    checkout_enabled: true,
  },
  business: {
    key: "business",
    name: "Business",
    description:
      "Full Cyber MOT with 10 monitored domains included, expandable to 25.",
    monthly_pence: 4999,
    annual_pence: 49990,
    included_domains: 10,
    // Domains 11–25 are billed per domain; domain 26 is rejected and routed to MSP.
    additional_domain_monthly_pence: 300,
    additional_domain_annual_pence: 3000,
    domain_hard_cap: 25,
    checkout_enabled: true,
  },
  enterprise: {
    key: "enterprise",
    name: "MSP",
    description:
      "For MSPs and advisors managing client portfolios. Base fee plus £3/month per monitored domain (minimum 10 domains).",
    // MSP has no flat monthly price: base + metered per-domain (minimum billed
    // quantity 10 → monthly floor £129.99). monthly_pence stays null so no
    // consumer can render MSP as a flat price.
    monthly_pence: null,
    annual_pence: null,
    base_monthly_pence: 9999,
    base_annual_pence: 99990,
    per_domain_monthly_pence: 300,
    per_domain_annual_pence: 3000,
    min_billed_domains: 10,
    floor_monthly_pence: 12999,
    floor_annual_pence: 129990,
    included_domains: 0,
    checkout_enabled: false,
  },
};

// 14-Day Full Trial rules (policy §4). The trial grants the full product
// (professional feature set) but exactly ONE monitored domain, expires
// fail-closed after 14 days, and never converts to a paid plan without
// explicit customer consent (no card is taken).
export const TRIAL_SPEC = {
  duration_days: 14,
  domains: 1,
  features_plan: "professional",
  card_required: false,
};

export function penceToGbp(pence) {
  if (pence === null || pence === undefined) return null;
  return Math.round(pence) / 100;
}

// Expected Stripe charge for a self-serve checkout of `plan` at `interval`.
// Used by the checkout guard to refuse a session whose Stripe price does not
// charge exactly what the canonical policy states.
export function expectedCheckoutAmountPence(plan, interval) {
  const entry = CANONICAL_PLANS[plan];
  if (!entry || !entry.checkout_enabled) return null;
  const pence = interval === "annual" ? entry.annual_pence : entry.monthly_pence;
  return Number.isInteger(pence) && pence > 0 ? pence : null;
}
