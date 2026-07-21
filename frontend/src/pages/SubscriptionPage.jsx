import { parseServerDate } from '../utils/dates'
/**
 * SubscriptionPage — workspace-level subscription and trial status.
 *
 * Route: /billing  (replaces account-level BillingPage.jsx at this route)
 *
 * Fetches: GET /api/workspaces/:id/subscription
 * Shows:
 *   - Current plan badge + plan description
 *   - Trial countdown card (prominent when trialing)
 *   - Plan limits summary (workspaces, domains, users, scans)
 *   - Plan features checklist
 *   - Upgrade CTA panel
 *   - Contact sales for Enterprise
 *
 * Workspace context: reads localStorage('cybermeters_workspace_id').
 * Falls back gracefully if no workspace is active.
 */
import { useState, useEffect } from 'react'
import { Link, useSearchParams } from 'react-router-dom'
import {
  CreditCard, Clock, CheckCircle, ArrowRight, Shield,
  Zap, Globe, Users, Calendar, BarChart2, FileText,
  Bell, AlertTriangle, Star, Lock, ChevronRight,
  RefreshCw, Building2, Mail,
} from 'lucide-react'
import { api } from '../api'

// ── Plan display config (visual only) ────────────────────────────────────────
// Prices are NEVER stated here: they come exclusively from the canonical plan
// API (GET /api/billing/plans, backed by the locked pricing policy). When live
// metadata is unavailable no price is shown — a stale local number could sell
// an amount the backend would refuse to charge.

const PLAN_META = {
  free: {
    label:       '14-Day Full Trial',
    color:       'text-gray-600',
    badge:       'bg-gray-100 text-gray-700 border-gray-200',
    ring:        'border-gray-200',
    description: 'Trial ended or no subscription: read-only access to your existing scans, reports and evidence. Choose a plan to resume monitoring.',
  },
  starter: {
    label:       'Starter',
    color:       'text-blue-600',
    badge:       'bg-blue-50 text-blue-700 border-blue-200',
    ring:        'border-blue-200',
    description: 'Full Cyber MOT for 1 monitored domain — scheduled scans, PDF reports, alerts and Business Risk Score.',
  },
  professional: {
    label:       'Professional',
    color:       'text-brand-600',
    badge:       'bg-brand-50 text-brand-700 border-brand-200',
    ring:        'border-brand-200',
    description: 'Up to 3 monitored domains, plus Cyber Essentials Readiness, third-party technology detection, Executive Dashboard and audit logs.',
  },
  business: {
    label:       'Business',
    color:       'text-purple-600',
    badge:       'bg-purple-50 text-purple-700 border-purple-200',
    ring:        'border-purple-200',
    description: '10 monitored domains included, plus Portfolio Monitoring, White Label reports and extended retention.',
  },
  enterprise: {
    label:       'MSP',
    color:       'text-amber-600',
    badge:       'bg-amber-50 text-amber-700 border-amber-200',
    ring:        'border-amber-200',
    description: 'For MSPs and advisors managing client portfolios — base fee plus per-domain pricing, sales-led onboarding.',
  },
}

const STATUS_CFG = {
  trialing:  { label: 'Trial',     dot: 'bg-blue-400',   pill: 'bg-blue-50 text-blue-700 border-blue-100'   },
  active:    { label: 'Active',    dot: 'bg-green-400',  pill: 'bg-green-50 text-green-700 border-green-100' },
  past_due:  { label: 'Past due',  dot: 'bg-amber-400',  pill: 'bg-amber-50 text-amber-700 border-amber-100' },
  canceled:  { label: 'Cancelled', dot: 'bg-red-400',    pill: 'bg-red-50 text-red-700 border-red-100'       },
  free:      { label: 'Free',      dot: 'bg-gray-300',   pill: 'bg-gray-50 text-gray-600 border-gray-100'    },
}
function statusCfg(s) { return STATUS_CFG[s] ?? STATUS_CFG.free }

// Feature gate display config
const GATE_DISPLAY = [
  { key: 'scheduled_scans', icon: Calendar, label: 'Scheduled scans'         },
  { key: 'alerts',          icon: Bell,     label: 'Email & in-app alerts'   },
  { key: 'pdf_reports',     icon: FileText, label: 'PDF report export'       },
  { key: 'multi_workspace', icon: Building2,label: 'Multiple workspaces'     },
  { key: 'team_members',    icon: Users,    label: 'Team member invitations' },
  { key: 'business_risk_score', icon: BarChart2, label: 'Business Risk Score' },
  { key: 'cyber_essentials',    icon: Shield,    label: 'Cyber Essentials Readiness' },
  // vendor_risk gates the live third-party technology surface; the retired
  // vendor-risk marketing claim must not be advertised — the honest label
  // states only what external observation actually provides.
  { key: 'vendor_risk',         icon: Globe,     label: 'Third-party technology detection' },
  { key: 'executive_dashboard', icon: Star,      label: 'Executive Risk Dashboard'   },
  { key: 'audit_logs',          icon: CheckCircle, label: 'Workspace Audit Logs'     },
  { key: 'portfolio_monitoring',icon: BarChart2, label: 'Portfolio Monitoring'       },
  { key: 'white_label',         icon: FileText,  label: 'White-label reports'        },
]

// Upgrade path from each plan
const UPGRADE_TARGET = {
  free:         'starter',
  starter:      'professional',
  professional: 'business',
  business:     'enterprise',
  enterprise:   null,
}

// ── Trial countdown card ──────────────────────────────────────────────────────

function TrialCountdown({ daysLeft, trialEnd, onUpgrade }) {
  const urgent = daysLeft <= 3
  const warning = daysLeft <= 7 && !urgent
  const bg    = urgent  ? 'bg-red-50 border-red-200'    :
                warning ? 'bg-amber-50 border-amber-200' :
                          'bg-blue-50 border-blue-200'
  const textH = urgent  ? 'text-red-800'  :
                warning ? 'text-amber-800' :
                          'text-blue-800'
  const textB = urgent  ? 'text-red-600'  :
                warning ? 'text-amber-600' :
                          'text-blue-600'
  const btnBg = urgent  ? 'bg-red-600 hover:bg-red-700'     :
                warning ? 'bg-amber-600 hover:bg-amber-700'  :
                          'bg-brand-600 hover:bg-brand-700'

  const endDate = trialEnd ? parseServerDate(trialEnd).toLocaleDateString('en-GB', {
    day: 'numeric', month: 'long', year: 'numeric',
  }) : null

  return (
    <div className={`rounded-2xl border p-5 ${bg}`}>
      <div className="flex items-start justify-between gap-4">
        <div className="flex items-start gap-3">
          <div className={`mt-0.5 w-8 h-8 rounded-lg flex items-center justify-center flex-shrink-0 ${urgent ? 'bg-red-100' : warning ? 'bg-amber-100' : 'bg-blue-100'}`}>
            <Clock className={`w-4 h-4 ${urgent ? 'text-red-600' : warning ? 'text-amber-600' : 'text-blue-600'}`} />
          </div>
          <div>
            <p className={`text-sm font-bold ${textH}`}>
              {urgent
                ? daysLeft === 0 ? 'Your trial ends today' : `${daysLeft} day${daysLeft !== 1 ? 's' : ''} left in your trial`
                : `${daysLeft} days left in your 14-day full trial`}
            </p>
            <p className={`text-xs mt-0.5 ${textB}`}>
              {endDate ? `Trial ends ${endDate}` : 'Upgrade to keep full access'}
              {urgent && ' — upgrade now to keep all features'}
            </p>
          </div>
        </div>
        <button
          onClick={onUpgrade}
          className={`flex-shrink-0 flex items-center gap-1.5 px-4 py-2 text-xs font-bold text-white rounded-xl transition-colors ${btnBg}`}
        >
          Upgrade now
          <ArrowRight className="w-3 h-3" />
        </button>
      </div>

      {/* Progress bar */}
      <div className="mt-4">
        <div className="flex items-center justify-between text-[10px] font-medium mb-1.5"
             style={{ color: urgent ? '#b91c1c' : warning ? '#92400e' : '#1d4ed8' }}>
          <span>Day {14 - daysLeft} of 14</span>
          <span>{daysLeft} days remaining</span>
        </div>
        <div className="h-1.5 bg-white/60 rounded-full overflow-hidden">
          <div
            className={`h-full rounded-full transition-all ${urgent ? 'bg-red-500' : warning ? 'bg-amber-500' : 'bg-blue-500'}`}
            style={{ width: `${((14 - daysLeft) / 14) * 100}%` }}
          />
        </div>
      </div>
    </div>
  )
}

// ── Plan card ─────────────────────────────────────────────────────────────────

function PlanCard({ plan, status, meta, livePlan, billingInterval, onUpgrade, subscriptionActive, trialActive, checkoutLoading, portalPlanChange = false }) {
  const scfg = statusCfg(trialActive ? 'trialing' : (status || 'free'))
  const upgradeTo = UPGRADE_TARGET[plan]
  // Price comes only from live canonical plan metadata; without it, no price
  // is displayed (never a stale local figure).
  //
  // The displayed amount must reflect the subscription's ACTUAL billing
  // interval: an annual subscriber is charged the annual price, so showing the
  // plan's monthly headline for them mis-states what they pay. When the
  // subscription bills annually, render the annual figure (with the monthly
  // equivalent as context); if the annual figure is unavailable from the live
  // API, show NO price — never the monthly number an annual customer is not
  // charged.
  const annualBilling = subscriptionActive && !trialActive && billingInterval === 'annual'
  const monthlyGbp = livePlan && Number.isFinite(livePlan.monthly_gbp) ? livePlan.monthly_gbp : null
  const annualGbp  = livePlan && Number.isFinite(livePlan.annual_gbp)  ? livePlan.annual_gbp  : null
  const annualEqMonthlyGbp = livePlan && Number.isFinite(livePlan.annual_equivalent_monthly_gbp)
    ? livePlan.annual_equivalent_monthly_gbp
    : null
  const mspFloor = annualBilling
    ? (livePlan?.pricing_model?.floor_annual_gbp ?? null)
    : (livePlan?.pricing_model?.floor_monthly_gbp ?? null)
  const shownGbp = annualBilling ? annualGbp : monthlyGbp

  return (
    <div className={`bg-white rounded-2xl border-2 p-5 ${meta.ring}`}>
      <div className="flex items-start justify-between gap-3 mb-4">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <span className={`text-xs font-black uppercase tracking-widest px-2.5 py-1 rounded-full border ${meta.badge}`}>
              {meta.label}
            </span>
            <span className={`flex items-center gap-1 text-[10px] font-bold px-2 py-0.5 rounded-full border ${scfg.pill}`}>
              <span className={`w-1.5 h-1.5 rounded-full ${scfg.dot}`} />
              {scfg.label}
            </span>
          </div>
          <p className="text-xs text-gray-500 mt-2 leading-relaxed max-w-sm">{meta.description}</p>
        </div>
        {shownGbp !== null && (
          <div className="text-right flex-shrink-0">
            {shownGbp === 0 ? (
              <p className="text-2xl font-black text-gray-800">£0</p>
            ) : (
              <>
                <p className="text-2xl font-black text-gray-800">£{shownGbp.toFixed(2)}</p>
                <p className="text-[10px] text-gray-400 font-medium">{annualBilling ? '/ year' : '/ month'}</p>
                {annualBilling && annualEqMonthlyGbp !== null && annualEqMonthlyGbp > 0 && (
                  <p className="text-[10px] text-gray-400 font-medium mt-0.5">≈ £{annualEqMonthlyGbp.toFixed(2)}/mo · billed annually</p>
                )}
              </>
            )}
          </div>
        )}
        {shownGbp === null && plan === 'enterprise' && (
          <div className="text-right flex-shrink-0">
            <p className="text-lg font-black text-amber-700">{mspFloor != null ? `from £${mspFloor.toFixed(2)}` : 'Contact us'}</p>
            <p className="text-[10px] text-gray-400 font-medium">{mspFloor != null ? `${annualBilling ? '/ year' : '/ month'} · contact us` : 'sales-led'}</p>
          </div>
        )}
      </div>

      {upgradeTo && upgradeTo !== 'enterprise' && (
        <button
          onClick={() => onUpgrade(upgradeTo)}
          disabled={checkoutLoading}
          className="w-full flex items-center justify-center gap-2 py-2.5 text-sm font-bold text-white bg-brand-600 hover:bg-brand-700 rounded-xl transition-colors disabled:opacity-60"
        >
          {checkoutLoading
            ? <><RefreshCw className="w-4 h-4 animate-spin" /> {portalPlanChange ? 'Opening billing portal…' : 'Opening checkout…'}</>
            : portalPlanChange
              ? <><span>Change plan in billing portal</span><ArrowRight className="w-4 h-4" /></>
              : <><span>Upgrade to {PLAN_META[upgradeTo]?.label}</span><ArrowRight className="w-4 h-4" /></>
          }
        </button>
      )}
      {upgradeTo === 'enterprise' && (
        <a
          href="mailto:sales@cybermeters.com?subject=CyberMeters%20MSP%20Enquiry"
          className="w-full flex items-center justify-center gap-2 py-2.5 text-sm font-bold text-amber-700 bg-amber-50 hover:bg-amber-100 border border-amber-200 rounded-xl transition-colors"
        >
          <Mail className="w-4 h-4" />
          Contact Sales for MSP
        </a>
      )}
      {!upgradeTo && (
        <div className="flex items-center gap-2 text-xs text-green-600 font-semibold">
          <CheckCircle className="w-4 h-4" />
          You're on our top plan
        </div>
      )}
    </div>
  )
}

// ── Plan limits summary ───────────────────────────────────────────────────────

function LimitsGrid({ limits }) {
  if (!limits) return null
  const items = [
    // Customer-facing value metric is monitored domains — lead with it. Internal
    // enforcement quotas (workspaces, scans/month, scheduled scans) are not
    // customer-facing plan value and are no longer rendered here.
    { label: 'Monitored domains', value: limits.domains,      icon: Globe },
    { label: 'Team members',      value: limits.users,        icon: Users },
    { label: 'Report history (days)', value: limits.history_days, icon: Clock },
  ]
  function fmt(v) {
    if (v === undefined || v === null) return '—'
    if (v >= 999999) return 'Unlimited'
    return v.toLocaleString()
  }
  return (
    <div className="grid grid-cols-2 sm:grid-cols-3 gap-3">
      {items.map(({ label, value, icon: Icon }) => (
        <div key={label} className="bg-white border border-gray-200/80 rounded-xl p-3 text-center">
          {/* Label on top (larger); number below and smaller. */}
          <Icon className="w-4 h-4 text-gray-300 mx-auto mb-1.5" />
          <p className="text-sm font-semibold text-gray-900 leading-snug">{label}</p>
          <p className="text-xs font-bold text-gray-600 mt-1 tabular-nums">{fmt(value)}</p>
        </div>
      ))}
    </div>
  )
}

// ── Features checklist ────────────────────────────────────────────────────────

function FeatureChecklist({ features }) {
  if (!features) return null
  const featureSet = new Set(features)
  return (
    <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
      {GATE_DISPLAY.map(({ key, icon: Icon, label }) => {
        const has = featureSet.has(key)
        return (
          <div
            key={key}
            className={`flex items-center gap-2.5 text-xs font-medium px-3 py-2 rounded-lg ${
              has ? 'text-gray-700' : 'text-gray-300'
            }`}
          >
            {has
              ? <CheckCircle className="w-3.5 h-3.5 text-green-500 flex-shrink-0" />
              : <Lock className="w-3.5 h-3.5 text-gray-300 flex-shrink-0" />
            }
            <Icon className={`w-3 h-3 flex-shrink-0 ${has ? 'text-gray-400' : 'text-gray-200'}`} />
            {label}
          </div>
        )
      })}
    </div>
  )
}

// ── Upgrade prompt (shown for free / trial-expired users) ─────────────────────

function UpgradePrompt({ plan, onUpgrade, checkoutLoading, livePlans }) {
  const upgradeTo = UPGRADE_TARGET[plan] ?? 'starter'
  if (upgradeTo === null) return null
  const starterPrice = livePlans?.starter && Number.isFinite(livePlans.starter.monthly_gbp)
    ? `£${livePlans.starter.monthly_gbp.toFixed(2)}`
    : null

  return (
    <div className="bg-gray-900 rounded-2xl p-6">
      <div className="flex items-start gap-3 mb-4">
        <div className="w-10 h-10 rounded-xl bg-brand-500/20 flex items-center justify-center flex-shrink-0">
          <Zap className="w-5 h-5 text-brand-400" />
        </div>
        <div>
          <h3 className="text-base font-bold text-white mb-1">
            {plan === 'free'
              ? 'Ready to unlock the full platform?'
              : `Upgrade to ${PLAN_META[upgradeTo]?.label}`}
          </h3>
          <p className="text-xs text-gray-400 leading-relaxed">
            {plan === 'free'
              ? `Get scheduled scans, PDF reports, email alerts, and Business Risk Score${starterPrice ? ` — starting at ${starterPrice}/mo` : ''}.`
              : `${PLAN_META[upgradeTo]?.description}`}
          </p>
        </div>
      </div>
      <div className="flex flex-col sm:flex-row gap-2">
        {upgradeTo !== 'enterprise' ? (
          <button
            onClick={() => onUpgrade(upgradeTo)}
            disabled={checkoutLoading}
            className="flex items-center justify-center gap-2 px-5 py-2.5 text-sm font-bold text-white bg-brand-600 hover:bg-brand-500 rounded-xl transition-colors disabled:opacity-60"
          >
            {checkoutLoading
              ? <><RefreshCw className="w-4 h-4 animate-spin" /> Opening checkout…</>
              : <><span>Upgrade to {PLAN_META[upgradeTo]?.label}</span><ArrowRight className="w-4 h-4" /></>
            }
          </button>
        ) : (
          <a
            href="mailto:sales@cybermeters.com?subject=CyberMeters%20MSP%20Enquiry"
            className="flex items-center justify-center gap-2 px-5 py-2.5 text-sm font-bold text-white bg-brand-600 hover:bg-brand-500 rounded-xl transition-colors"
          >
            <Mail className="w-4 h-4" />
            Contact Sales for MSP
          </a>
        )}
        <Link
          to="/pricing"
          className="flex items-center justify-center gap-1.5 px-5 py-2.5 text-sm font-semibold text-gray-400 hover:text-white bg-white/10 hover:bg-white/20 rounded-xl transition-colors"
        >
          Compare all plans
          <ChevronRight className="w-3.5 h-3.5" />
        </Link>
      </div>
      <p className="text-[10px] text-gray-500 mt-3">No credit card required to start a trial · Cancel anytime</p>
    </div>
  )
}

// ── Main page ─────────────────────────────────────────────────────────────────

export default function SubscriptionPage() {
  const [sub,            setSub]            = useState(null)
  const [livePlans,      setLivePlans]      = useState(null)
  const [loading,        setLoading]        = useState(true)
  const [error,          setError]          = useState(null)
  const [checkoutLoading, setCheckoutLoading] = useState(false)
  const [checkoutError,   setCheckoutError]   = useState(null)
  const [portalLoading,   setPortalLoading]   = useState(false)
  const [portalError,     setPortalError]     = useState(null)
  const [searchParams, setSearchParams] = useSearchParams()

  const workspaceId = typeof window !== 'undefined'
    ? localStorage.getItem('cybermeters_workspace_id')
    : null

  // Read success/canceled URL params set by Stripe redirect
  const stripeSuccess  = searchParams.get('success')  === 'true'
  const stripeCanceled = searchParams.get('canceled')  === 'true'

  // Clear URL params after 5s so they don't persist on reload
  useEffect(() => {
    if (!stripeSuccess && !stripeCanceled) return
    const t = setTimeout(() => setSearchParams({}, { replace: true }), 5000)
    return () => clearTimeout(t)
  }, [stripeSuccess, stripeCanceled, setSearchParams])

  useEffect(() => {
    if (!workspaceId) { setLoading(false); return }
    let cancelled = false
    async function load() {
      try {
        const data = await api.getWorkspaceSubscription(workspaceId)
        if (!cancelled) setSub(data)
      } catch (e) {
        if (!cancelled) setError(e?.message || 'Failed to load subscription')
      } finally {
        if (!cancelled) setLoading(false)
      }
    }
    load()
    return () => { cancelled = true }
  }, [workspaceId])

  // Live canonical plan metadata (prices). Optional: when unavailable the page
  // simply shows no prices rather than any local figure.
  useEffect(() => {
    let cancelled = false
    api.getBillingPlans()
      .then((data) => {
        if (cancelled || !Array.isArray(data?.plans)) return
        const byKey = {}
        for (const p of data.plans) byKey[p.key] = p
        setLivePlans(byKey)
      })
      .catch(() => { /* fail honestly — no price shown */ })
    return () => { cancelled = true }
  }, [])

  // B3: an active PAID Stripe subscription changes plan in the Stripe billing
  // portal (which switches the existing subscription and prorates) — never via
  // a fresh checkout, which would create a second subscription. The backend
  // enforces this structurally; the UI routes there directly and says so.
  const paidPlanChangeViaPortal =
    (sub?.subscription_active ?? false) &&
    !(sub?.trial_active ?? false) &&
    Boolean(sub?.stripe_subscription_id)

  async function handleUpgrade(targetPlan = 'professional') {
    if (!workspaceId) return
    // Enterprise → contact sales, never self-serve
    if (targetPlan === 'enterprise') {
      window.location.href = 'mailto:sales@cybermeters.com?subject=CyberMeters%20MSP%20Enquiry'
      return
    }
    if (paidPlanChangeViaPortal) {
      await handleManageBilling()
      return
    }
    setCheckoutError(null)
    setCheckoutLoading(true)
    try {
      const result = await api.startWorkspaceCheckout(workspaceId, targetPlan, 'monthly')
      if (result?.url) {
        window.location.href = result.url
      } else {
        setCheckoutError('Unexpected response from checkout. Please try again.')
      }
    } catch (e) {
      setCheckoutError(e?.message || 'Failed to start checkout. Please try again.')
    } finally {
      setCheckoutLoading(false)
    }
  }

  async function handleManageBilling() {
    if (!workspaceId) return
    setPortalError(null)
    setPortalLoading(true)
    try {
      const result = await api.openWorkspaceBillingPortal(workspaceId)
      if (result?.url) {
        window.location.href = result.url
      } else {
        setPortalError('Unexpected response from billing portal. Please try again.')
      }
    } catch (e) {
      setPortalError(e?.message || 'Failed to open billing portal. Please try again.')
    } finally {
      setPortalLoading(false)
    }
  }

  // Derived state
  const plan              = sub?.plan                 ?? 'free'
  const status            = sub?.status               ?? 'free'
  const trialActive       = sub?.trial_active         ?? false
  const trialRemainingDays = sub?.trial_remaining_days ?? 0
  const subscriptionActive = sub?.subscription_active ?? false
  const meta              = PLAN_META[plan] ?? PLAN_META.free
  const limits            = sub?.limits    ?? null
  const features          = sub?.features  ?? []

  // Billing lifecycle state — grace period, post-grace downgrade, scheduled cancellation
  const graceActive       = sub?.grace_period_active === true
  const graceEndsAt       = sub?.grace_period_ends_at ?? null
  const pastDueExpired    = status === 'past_due' && !graceActive
  const cancelScheduled   = (sub?.cancel_at_period_end === true) && subscriptionActive && !trialActive
  const fmtDay = (v) => {
    if (!v) return null
    const d = parseServerDate(v)
    return Number.isNaN(d.getTime()) ? null : d.toLocaleDateString('en-GB', { day: 'numeric', month: 'long', year: 'numeric' })
  }

  // ── Loading ────────────────────────────────────────────────────────────────

  if (loading) {
    return (
      <div className="max-w-2xl mx-auto px-4 py-10">
        <div className="animate-pulse space-y-4">
          <div className="h-6 bg-gray-100 rounded w-1/3" />
          <div className="h-32 bg-gray-100 rounded-2xl" />
          <div className="h-24 bg-gray-100 rounded-2xl" />
          <div className="grid grid-cols-3 gap-3">
            {[...Array(6)].map((_, i) => <div key={i} className="h-20 bg-gray-100 rounded-xl" />)}
          </div>
        </div>
      </div>
    )
  }

  // ── No workspace ───────────────────────────────────────────────────────────

  if (!workspaceId) {
    return (
      <div className="max-w-2xl mx-auto px-4 py-10 text-center">
        <Building2 className="w-10 h-10 text-gray-300 mx-auto mb-3" />
        <h2 className="text-base font-bold text-gray-700 mb-1">No active workspace</h2>
        <p className="text-sm text-gray-400">Select a workspace to view subscription details.</p>
      </div>
    )
  }

  // ── Error ──────────────────────────────────────────────────────────────────

  if (error) {
    return (
      <div className="max-w-2xl mx-auto px-4 py-10">
        <div className="flex items-center gap-2 text-sm text-red-600 bg-red-50 border border-red-100 px-4 py-3 rounded-xl">
          <AlertTriangle className="w-4 h-4 flex-shrink-0" />
          {error}
        </div>
      </div>
    )
  }

  // ── Render ─────────────────────────────────────────────────────────────────

  return (
    <div className="max-w-2xl mx-auto px-4 py-8 space-y-6">

      {/* ── Header ── */}
      <div className="flex items-start justify-between gap-3">
        <div className="flex items-center gap-3">
          <div className="w-9 h-9 rounded-xl bg-brand-50 flex items-center justify-center">
            <CreditCard className="w-5 h-5 text-brand-600" />
          </div>
          <div>
            <h1 className="text-lg font-black text-gray-900">Subscription</h1>
            <p className="text-xs text-gray-400">Manage your plan and billing</p>
          </div>
        </div>
        {/* Manage Billing button — only when an active paid subscription with Stripe exists */}
        {sub?.stripe_subscription_id && (
          <button
            onClick={handleManageBilling}
            disabled={portalLoading}
            className="flex items-center gap-1.5 px-4 py-2 text-xs font-semibold text-gray-600 bg-white border border-gray-200 hover:border-gray-300 hover:text-gray-800 rounded-xl transition-colors disabled:opacity-50"
          >
            {portalLoading ? (
              <RefreshCw className="w-3.5 h-3.5 animate-spin" />
            ) : (
              <CreditCard className="w-3.5 h-3.5" />
            )}
            Manage Billing
          </button>
        )}
      </div>

      {/* ── Stripe return banners ── */}
      {stripeSuccess && (
        <div className="flex items-center gap-3 bg-green-50 border border-green-200 rounded-2xl px-4 py-3">
          <CheckCircle className="w-5 h-5 text-green-600 flex-shrink-0" />
          <div>
            <p className="text-sm font-bold text-green-800">Payment successful — plan upgraded!</p>
            <p className="text-xs text-green-600 mt-0.5">Your new plan features are now active.</p>
          </div>
        </div>
      )}
      {stripeCanceled && (
        <div className="flex items-center gap-3 bg-gray-50 border border-gray-200 rounded-2xl px-4 py-3">
          <AlertTriangle className="w-4 h-4 text-gray-400 flex-shrink-0" />
          <p className="text-sm text-gray-600">Checkout cancelled — no changes were made.</p>
        </div>
      )}

      {/* ── Checkout / portal error banners ── */}
      {checkoutError && (
        <div className="flex items-start gap-2 bg-red-50 border border-red-200 rounded-xl px-4 py-3">
          <AlertTriangle className="w-4 h-4 text-red-500 flex-shrink-0 mt-0.5" />
          <p className="text-xs text-red-700">{checkoutError}</p>
        </div>
      )}
      {portalError && (
        <div className="flex items-start gap-2 bg-red-50 border border-red-200 rounded-xl px-4 py-3">
          <AlertTriangle className="w-4 h-4 text-red-500 flex-shrink-0 mt-0.5" />
          <p className="text-xs text-red-700">{portalError}</p>
        </div>
      )}

      {/* ── Payment grace period — plan still active while Stripe retries ── */}
      {graceActive && (
        <div className="flex items-start gap-3 bg-amber-50 border border-amber-200 rounded-2xl p-4">
          <AlertTriangle className="w-5 h-5 text-amber-600 flex-shrink-0 mt-0.5" />
          <div className="flex-1 min-w-0">
            <p className="text-sm font-bold text-amber-800">Payment issue — your plan is still active</p>
            <p className="text-xs text-amber-700 mt-0.5 leading-relaxed">
              Your latest payment could not be processed. Your {meta?.name || 'paid'} plan remains fully active
              {fmtDay(graceEndsAt) ? <> until <span className="font-semibold">{fmtDay(graceEndsAt)}</span></> : null} while the charge is retried.
              Update your payment method to keep your plan.
            </p>
            <button onClick={handleManageBilling} disabled={portalLoading}
              className="mt-2 inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-bold text-white bg-amber-600 hover:bg-amber-700 rounded-lg transition-colors disabled:opacity-50">
              {portalLoading ? <RefreshCw className="w-3.5 h-3.5 animate-spin" /> : <CreditCard className="w-3.5 h-3.5" />}
              Update payment method
            </button>
          </div>
        </div>
      )}

      {/* ── Post-grace downgrade — payment never collected ── */}
      {pastDueExpired && (
        <div className="flex items-start gap-3 bg-red-50 border border-red-200 rounded-2xl p-4">
          <AlertTriangle className="w-5 h-5 text-red-600 flex-shrink-0 mt-0.5" />
          <div className="flex-1 min-w-0">
            <p className="text-sm font-bold text-red-800">Your workspace moved to the Free plan</p>
            <p className="text-xs text-red-700 mt-0.5 leading-relaxed">
              Payment could not be collected, so paid features are paused. Your data and settings are kept safe.
              Update your payment method to restore your plan.
            </p>
            <button onClick={handleManageBilling} disabled={portalLoading}
              className="mt-2 inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-bold text-white bg-red-600 hover:bg-red-700 rounded-lg transition-colors disabled:opacity-50">
              {portalLoading ? <RefreshCw className="w-3.5 h-3.5 animate-spin" /> : <CreditCard className="w-3.5 h-3.5" />}
              Update payment method
            </button>
          </div>
        </div>
      )}

      {/* ── Scheduled cancellation — access continues until period end ── */}
      {cancelScheduled && (
        <div className="flex items-start gap-3 bg-blue-50 border border-blue-200 rounded-2xl p-4">
          <AlertTriangle className="w-5 h-5 text-blue-600 flex-shrink-0 mt-0.5" />
          <div className="flex-1 min-w-0">
            <p className="text-sm font-bold text-blue-800">Your subscription is scheduled to cancel</p>
            <p className="text-xs text-blue-700 mt-0.5 leading-relaxed">
              You keep full access to your {meta?.name || 'paid'} plan
              {fmtDay(sub?.current_period_end) ? <> until <span className="font-semibold">{fmtDay(sub.current_period_end)}</span></> : ' until the end of your billing period'},
              then your workspace moves to the Free plan. Changed your mind? You can resume your subscription any time before then.
            </p>
            <button onClick={handleManageBilling} disabled={portalLoading}
              className="mt-2 inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-bold text-blue-700 bg-white border border-blue-200 hover:border-blue-300 rounded-lg transition-colors disabled:opacity-50">
              {portalLoading ? <RefreshCw className="w-3.5 h-3.5 animate-spin" /> : <CreditCard className="w-3.5 h-3.5" />}
              Resume subscription
            </button>
          </div>
        </div>
      )}

      {/* ── Trial countdown (shown only when trialing) ── */}
      {trialActive && (
        <TrialCountdown
          daysLeft={trialRemainingDays}
          trialEnd={sub?.trial_end}
          onUpgrade={() => handleUpgrade('professional')}
        />
      )}

      {/* ── Trial expired banner ── */}
      {!trialActive && !subscriptionActive && status === 'trialing' && (
        <div className="flex items-start gap-3 bg-amber-50 border border-amber-200 rounded-2xl p-4">
          <AlertTriangle className="w-5 h-5 text-amber-600 flex-shrink-0 mt-0.5" />
          <div>
            <p className="text-sm font-bold text-amber-800">Your trial has ended</p>
            <p className="text-xs text-amber-600 mt-0.5">
              Your workspace is now on the Free plan. Upgrade to restore full access.
            </p>
          </div>
        </div>
      )}

      {/* ── Current plan card ── */}
      <PlanCard
        plan={plan}
        status={status}
        meta={meta}
        livePlan={livePlans?.[plan] ?? null}
        billingInterval={sub?.billing_interval ?? 'monthly'}
        onUpgrade={handleUpgrade}
        subscriptionActive={subscriptionActive}
        trialActive={trialActive}
        checkoutLoading={checkoutLoading || (paidPlanChangeViaPortal && portalLoading)}
        portalPlanChange={paidPlanChangeViaPortal}
      />

      {/* ── Plan limits ── */}
      {limits && (
        <div>
          <h2 className="text-xs font-bold text-gray-500 uppercase tracking-widest mb-3">Plan limits</h2>
          <LimitsGrid limits={limits} />
        </div>
      )}

      {/* ── Features ── */}
      <div>
        <h2 className="text-xs font-bold text-gray-500 uppercase tracking-widest mb-3">Included features</h2>
        <div className="bg-white border border-gray-100 rounded-2xl p-4">
          <FeatureChecklist features={features} />
        </div>
      </div>

      {/* ── Upgrade prompt (free + post-trial) ── */}
      {!subscriptionActive && !trialActive && (
        <UpgradePrompt plan={plan} onUpgrade={handleUpgrade} checkoutLoading={checkoutLoading} livePlans={livePlans} />
      )}

      {/* ── Trial tip (when still in trial) ── */}
      {trialActive && (
        <div className="bg-brand-50 border border-brand-100 rounded-2xl p-4 flex items-start gap-3">
          <Shield className="w-5 h-5 text-brand-600 flex-shrink-0 mt-0.5" />
          <div>
            <p className="text-sm font-bold text-brand-800 mb-1">You're on the 14-day full trial</p>
            <p className="text-xs text-brand-600 leading-relaxed">
              The full product is active for 1 monitored domain. Upgrade before your trial ends to keep
              access to Cyber Essentials Readiness, the Executive Dashboard, and more.
            </p>
          </div>
        </div>
      )}

      {/* ── Compare plans link ── */}
      <div className="text-center">
        <Link
          to="/pricing"
          className="inline-flex items-center gap-1.5 text-xs font-semibold text-gray-400 hover:text-gray-700 transition-colors"
        >
          Compare all plans and pricing
          <ChevronRight className="w-3 h-3" />
        </Link>
      </div>

    </div>
  )
}
