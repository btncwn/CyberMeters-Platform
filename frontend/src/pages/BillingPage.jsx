/**
 * BillingPage — Customer Portal v1
 *
 * Stripe-inspired billing experience:
 *   - Plan overview card with price, status, renewal date
 *   - Usage meters (domains, users, scheduled scans, reports)
 *   - Plan comparison widget (Starter / Professional / Business)
 *   - Quick-action sidebar
 *   - Billing history table + empty state
 *   - Trust indicators footer
 *
 * Route: /billing
 * APIs: getSubscription(), getSubscriptionLimits()
 * Invoices: mock state (no API yet — replace when available)
 */

import { useState, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import {
  CreditCard, Zap, Users, Globe, FileBarChart2, Calendar,
  ArrowRight, Check, ChevronRight, Shield, Clock,
  AlertTriangle, Download, RefreshCw, Star, TrendingUp,
  FileText, Building2,
} from 'lucide-react'
import { api } from '../api'

// ── Plan metadata ─────────────────────────────────────────────────────────────

const PLAN_META = {
  free:         { label: 'Free',         monthly: 0,    annual: 0,    annualSave: 0   },
  starter:      { label: 'Starter',      monthly: 29,   annual: 23,   annualSave: 72  },
  professional: { label: 'Professional', monthly: 149,  annual: 119,  annualSave: 360 },
  business:     { label: 'Business',     monthly: 399,  annual: 319,  annualSave: 960 },
  enterprise:   { label: 'Enterprise',   monthly: null, annual: null, annualSave: 0   },
}

const PLAN_BADGE = {
  free:         'bg-gray-100 text-gray-600 border-gray-200',
  starter:      'bg-blue-50 text-blue-700 border-blue-200',
  professional: 'bg-brand-50 text-brand-700 border-brand-200',
  business:     'bg-purple-50 text-purple-700 border-purple-200',
  enterprise:   'bg-amber-50 text-amber-700 border-amber-200',
}

const PLAN_FEATURES = {
  starter: [
    '3 workspaces',
    '25 domains',
    '5 users',
    '3 scheduled scans / workspace',
    'Standard PDF reports',
    'Email notifications',
  ],
  professional: [
    '10 workspaces',
    '100 domains',
    '25 users',
    '20 scheduled scans / workspace',
    'Executive reports',
    'Business Risk Score',
    'Cyber Essentials readiness',
    'Portfolio dashboard',
  ],
  business: [
    'Unlimited workspaces',
    '500 domains',
    '100 users',
    '100 scheduled scans / workspace',
    'White-label reports',
    'MSP dashboard',
    'Full API access',
    'Priority support',
  ],
}

const STATUS_CFG = {
  active:    { label: 'Active',    dot: 'bg-green-400',  pill: 'bg-green-50 text-green-700 border-green-100'  },
  trial:     { label: 'Trialling', dot: 'bg-blue-400',   pill: 'bg-blue-50 text-blue-700 border-blue-100'     },
  trialing:  { label: 'Trialling', dot: 'bg-blue-400',   pill: 'bg-blue-50 text-blue-700 border-blue-100'     },
  past_due:  { label: 'Past Due',  dot: 'bg-amber-400',  pill: 'bg-amber-50 text-amber-700 border-amber-100'  },
  cancelled: { label: 'Cancelled', dot: 'bg-gray-300',   pill: 'bg-gray-50 text-gray-500 border-gray-200'     },
  canceled:  { label: 'Cancelled', dot: 'bg-gray-300',   pill: 'bg-gray-50 text-gray-500 border-gray-200'     },
}

// ── Utility helpers ───────────────────────────────────────────────────────────

function fmtDate(iso) {
  if (!iso) return '—'
  try {
    return new Date(iso).toLocaleDateString('en-GB', {
      day: 'numeric', month: 'long', year: 'numeric',
    })
  } catch { return '—' }
}

function fmtMonthYear(iso) {
  if (!iso) return '—'
  try {
    return new Date(iso).toLocaleDateString('en-GB', { month: 'long', year: 'numeric' })
  } catch { return '—' }
}

function usagePct(used, limit) {
  if (!limit || limit >= 999999) return 0
  return Math.min(100, Math.round(((used ?? 0) / limit) * 100))
}

function usageBarColor(pct) {
  if (pct >= 95) return 'bg-red-500'
  if (pct >= 80) return 'bg-amber-400'
  return 'bg-brand-600'
}

// ── Skeleton loader ───────────────────────────────────────────────────────────

function Skel({ className = '' }) {
  return <div className={`animate-pulse bg-gray-100 rounded-xl ${className}`} />
}

// ── Status pill ───────────────────────────────────────────────────────────────

function StatusPill({ status }) {
  const s = String(status || 'active').toLowerCase()
  const cfg = STATUS_CFG[s] ?? STATUS_CFG.active
  return (
    <span className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full border text-xs font-semibold ${cfg.pill}`}>
      <span className={`w-1.5 h-1.5 rounded-full flex-shrink-0 ${cfg.dot}`} />
      {cfg.label}
    </span>
  )
}

// ── Plan badge ────────────────────────────────────────────────────────────────

function PlanBadge({ plan }) {
  const meta = PLAN_META[plan] ?? PLAN_META.free
  const badge = PLAN_BADGE[plan] ?? PLAN_BADGE.free
  return (
    <span className={`inline-flex items-center px-3 py-1 rounded-full border text-xs font-bold uppercase tracking-wider ${badge}`}>
      {meta.label}
    </span>
  )
}

// ── Usage card ────────────────────────────────────────────────────────────────

function UsageCard({ icon: Icon, label, used, limit }) {
  const unlimited = !limit || limit >= 999999
  const pct       = unlimited ? 0 : usagePct(used, limit)
  const barColor  = unlimited ? 'bg-brand-300' : usageBarColor(pct)
  const remaining = unlimited ? null : (limit - (used ?? 0))

  return (
    <div className="bg-white rounded-2xl border border-gray-100 shadow-card p-5 hover:shadow-card-md transition-all duration-200 hover:-translate-y-px">
      {/* Header */}
      <div className="flex items-start justify-between mb-4">
        <div className="w-9 h-9 rounded-xl bg-gray-50 border border-gray-100 flex items-center justify-center flex-shrink-0">
          <Icon className="w-4 h-4 text-gray-400" />
        </div>
        <span className="text-2xl font-bold text-gray-900 tabular-nums leading-none">
          {used ?? 0}
        </span>
      </div>

      {/* Label + count */}
      <div className="mb-3">
        <div className="text-[10px] font-bold text-gray-400 uppercase tracking-widest mb-0.5">{label}</div>
        <div className="text-xs text-gray-500 font-medium">
          {unlimited ? 'Unlimited' : `of ${limit} total`}
        </div>
      </div>

      {/* Progress bar */}
      <div className="h-1 bg-gray-100 rounded-full overflow-hidden mb-2">
        <div
          className={`h-full rounded-full transition-all duration-700 ease-out ${barColor}`}
          style={{ width: unlimited ? '100%' : `${pct}%` }}
        />
      </div>

      {/* Footer */}
      {!unlimited && (
        <div className="flex justify-between text-[10px] font-semibold tabular-nums">
          <span className={pct >= 80 ? 'text-amber-600' : 'text-gray-400'}>{pct}% used</span>
          <span className="text-gray-400">{remaining} free</span>
        </div>
      )}
    </div>
  )
}

// ── Plan comparison card ──────────────────────────────────────────────────────

function PlanCard({ planKey, currentPlan, interval, onUpgrade }) {
  const meta        = PLAN_META[planKey]
  const features    = PLAN_FEATURES[planKey] || []
  const isCurrent   = currentPlan === planKey
  const isPro       = planKey === 'professional'
  const price       = interval === 'annual' ? meta.annual : meta.monthly
  const isUpgrade   = ['free', 'starter'].includes(currentPlan) && planKey !== 'starter'

  return (
    <div className={`
      relative flex flex-col rounded-2xl border p-5 transition-all duration-200
      ${isCurrent
        ? 'border-brand-300 bg-brand-50/60 shadow-card-md ring-1 ring-brand-200'
        : isPro
          ? 'border-brand-200 bg-white hover:shadow-card-md hover:border-brand-300'
          : 'border-gray-100 bg-white hover:shadow-card'}
    `}>

      {/* Badge row */}
      <div className="flex items-center gap-1.5 min-h-[22px] mb-3">
        {isCurrent && (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 bg-brand-600 text-white rounded-full text-[9px] font-bold uppercase tracking-wider">
            <Check className="w-2.5 h-2.5" />
            Current
          </span>
        )}
        {isPro && !isCurrent && (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 bg-amber-50 text-amber-700 border border-amber-200 rounded-full text-[9px] font-bold uppercase tracking-wider">
            <Star className="w-2.5 h-2.5 fill-current" />
            Popular
          </span>
        )}
      </div>

      {/* Plan name */}
      <h3 className="text-sm font-bold text-gray-900 mb-1">{meta.label}</h3>

      {/* Price */}
      <div className="flex items-end gap-1 mb-1">
        <span className="text-2xl font-bold text-gray-900 tabular-nums">
          {price === null ? 'Custom' : price === 0 ? 'Free' : `£${price}`}
        </span>
        {price !== null && price > 0 && (
          <span className="text-xs text-gray-400 mb-0.5">/mo</span>
        )}
      </div>

      {/* Annual savings label */}
      {interval === 'annual' && meta.annualSave > 0 ? (
        <p className="text-[10px] text-green-600 font-semibold mb-4">
          Save £{meta.annualSave}/year
        </p>
      ) : (
        <p className="text-[10px] text-gray-300 mb-4">&nbsp;</p>
      )}

      {/* Feature list */}
      <ul className="flex-1 space-y-1.5 mb-5">
        {features.slice(0, 6).map(f => (
          <li key={f} className="flex items-start gap-1.5 text-[11px] text-gray-600">
            <Check className="w-3 h-3 text-brand-500 flex-shrink-0 mt-px" />
            <span>{f}</span>
          </li>
        ))}
      </ul>

      {/* CTA */}
      {isCurrent ? (
        <div className="text-center py-2 text-[11px] font-bold text-brand-600">
          ✓ Current plan
        </div>
      ) : planKey === 'enterprise' ? (
        <button
          onClick={() => onUpgrade('enterprise')}
          className="w-full py-2 rounded-xl text-[11px] font-semibold border border-gray-200 text-gray-700 hover:bg-gray-50 transition-all"
        >
          Contact Sales
        </button>
      ) : (
        <button
          onClick={() => onUpgrade(planKey)}
          className={`
            w-full py-2 rounded-xl text-[11px] font-semibold transition-all duration-150 border
            ${isUpgrade || isPro
              ? 'border-brand-500 bg-brand-600 text-white hover:bg-brand-700 hover:border-brand-700'
              : 'border-gray-200 text-gray-700 hover:bg-gray-50'}
          `}
        >
          {isUpgrade ? 'Upgrade' : 'Switch plan'} →
        </button>
      )}
    </div>
  )
}

// ── Action row (sidebar) ─────────────────────────────────────────────────────

function ActionRow({ icon: Icon, label, desc, danger = false, onClick }) {
  return (
    <button
      onClick={onClick}
      className={`
        group w-full flex items-center gap-3 p-3 rounded-xl border transition-all duration-150 text-left
        ${danger
          ? 'border-transparent hover:border-red-100 hover:bg-red-50'
          : 'border-transparent hover:border-gray-100 hover:bg-gray-50'}
      `}
    >
      <div className={`
        w-8 h-8 rounded-xl flex items-center justify-center flex-shrink-0 transition-colors
        ${danger
          ? 'bg-red-50 group-hover:bg-red-100'
          : 'bg-gray-50 group-hover:bg-brand-50'}
      `}>
        <Icon className={`w-3.5 h-3.5 transition-colors ${danger ? 'text-red-500' : 'text-gray-500 group-hover:text-brand-600'}`} />
      </div>
      <div className="flex-1 min-w-0">
        <div className={`text-xs font-semibold ${danger ? 'text-red-600' : 'text-gray-800'}`}>
          {label}
        </div>
        {desc && (
          <div className="text-[10px] text-gray-400 mt-0.5 truncate">{desc}</div>
        )}
      </div>
      <ChevronRight className={`
        w-3.5 h-3.5 flex-shrink-0 transition-all
        ${danger ? 'text-red-200 group-hover:text-red-400 group-hover:translate-x-0.5' : 'text-gray-200 group-hover:text-gray-400 group-hover:translate-x-0.5'}
      `} />
    </button>
  )
}

// ── Billing history empty state ───────────────────────────────────────────────

function EmptyInvoices() {
  return (
    <div className="flex flex-col items-center justify-center py-16 text-center px-6">
      <div className="w-14 h-14 rounded-2xl bg-gray-50 border border-gray-100 flex items-center justify-center mb-4">
        <FileText className="w-6 h-6 text-gray-200" />
      </div>
      <h3 className="text-sm font-semibold text-gray-700 mb-1.5">No invoices yet</h3>
      <p className="text-xs text-gray-400 leading-relaxed max-w-[220px]">
        Your invoices will appear here once your first billing cycle completes.
      </p>
    </div>
  )
}

// ── Section heading ───────────────────────────────────────────────────────────

function SectionLabel({ children }) {
  return (
    <p className="text-[10px] font-bold text-gray-400 uppercase tracking-widest mb-3 px-0.5">
      {children}
    </p>
  )
}

// ── Main page ─────────────────────────────────────────────────────────────────

export default function BillingPage() {
  const navigate = useNavigate()

  const [loading, setLoading]         = useState(true)
  const [subscription, setSubscription] = useState(null)
  const [limits, setLimits]           = useState(null)
  const [billingInterval, setBillingInterval] = useState('monthly')
  const [apiError, setApiError]       = useState(null)
  const [portalLoading, setPortalLoading] = useState(false)

  // Replace with real API when invoice endpoint is available
  const invoices = []

  useEffect(() => {
    let cancelled = false
    async function load() {
      try {
        const [subRes, limRes] = await Promise.all([
          api.getSubscription(),
          api.getSubscriptionLimits(),
        ])
        if (cancelled) return
        setSubscription(subRes?.subscription ?? null)
        setLimits(limRes ?? null)
      } catch (e) {
        if (cancelled) return
        setApiError(e?.message || 'Failed to load billing data')
      } finally {
        if (!cancelled) setLoading(false)
      }
    }
    load()
    return () => { cancelled = true }
  }, [])

  // Derived values
  const plan         = subscription?.plan || limits?.plan || 'free'
  const status       = subscription?.status || 'active'
  const periodEnd    = subscription?.current_period_end
  const createdAt    = subscription?.created_at
  const planMeta     = PLAN_META[plan] ?? PLAN_META.free
  const price        = billingInterval === 'annual' ? planMeta.annual : planMeta.monthly
  const usage        = limits?.usage    ?? {}
  const lims         = limits?.limits   ?? {}
  const isPaidPlan   = plan !== 'free'
  const canUpgrade   = plan === 'free' || plan === 'starter'

  async function handleUpgrade(targetPlan = 'professional') {
    setApiError(null)
    if (!targetPlan || targetPlan === 'free') { navigate('/pricing'); return }
    if (targetPlan === 'enterprise') {
      window.location.href = 'mailto:hello@cybermeters.com?subject=CyberMeters%20Enterprise'
      return
    }
    try {
      const origin = window.location.origin
      const res = await api.startCheckout(
        targetPlan,
        billingInterval,
        `${origin}/checkout/success`,
        `${origin}/checkout/cancel`,
      )
      if (res?.checkout_url) { window.location.href = res.checkout_url }
      else throw new Error('Checkout URL was not returned')
    } catch (e) {
      setApiError(e?.message || 'Could not start checkout. Please try again.')
    }
  }

  async function handleManageSubscription() {
    setApiError(null)
    setPortalLoading(true)
    try {
      const res = await api.openBillingPortal(window.location.origin + '/billing')
      if (res?.portal_url) {
        window.location.href = res.portal_url
        return
      }
      throw new Error('Billing portal URL was not returned')
    } catch (e) {
      setApiError(e?.message || 'Could not open billing portal')
    } finally {
      setPortalLoading(false)
    }
  }

  return (
    <div className="max-w-5xl mx-auto px-4 sm:px-6 py-8 sm:py-12">

      {/* ── Page header ──────────────────────────────────────────────────── */}
      <div className="flex flex-wrap items-start justify-between gap-4 mb-8">
        <div>
          <h1 className="text-2xl font-bold text-gray-900 tracking-tight">Billing</h1>
          <p className="text-sm text-gray-400 mt-0.5">
            Manage your subscription, usage, and invoices
          </p>
        </div>
        {!loading && <PlanBadge plan={plan} />}
      </div>

      {/* ── Error banner ─────────────────────────────────────────────────── */}
      {apiError && (
        <div className="mb-6 flex items-center gap-3 p-4 bg-red-50 border border-red-100 rounded-2xl">
          <AlertTriangle className="w-4 h-4 text-red-500 flex-shrink-0" />
          <p className="text-sm text-red-700">{apiError}</p>
        </div>
      )}

      {/* ══════════════════════════════════════════════════════════════════ */}
      {/* SECTION 1 — Plan overview card                                   */}
      {/* ══════════════════════════════════════════════════════════════════ */}
      <div className="bg-white rounded-2xl border border-gray-100 shadow-card-md overflow-hidden mb-6">

        {/* Main content */}
        <div className="p-7 sm:p-8">
          <div className="flex flex-col sm:flex-row sm:items-start gap-6">

            {/* Left — plan identity */}
            <div className="flex-1 min-w-0">
              <div className="flex items-center gap-3 mb-5">
                <div className="w-11 h-11 rounded-xl bg-brand-50 border border-brand-100 flex items-center justify-center flex-shrink-0">
                  <Shield className="w-5 h-5 text-brand-600" />
                </div>
                <div>
                  <p className="text-[10px] font-bold text-gray-400 uppercase tracking-widest mb-0.5">
                    Current Plan
                  </p>
                  {loading
                    ? <Skel className="h-7 w-36 mt-1" />
                    : <h2 className="text-2xl font-bold text-gray-900 tracking-tight leading-none">
                        {planMeta.label}
                      </h2>
                  }
                </div>
              </div>

              {/* Status + dates row */}
              {loading ? (
                <div className="flex gap-2">
                  <Skel className="h-6 w-16" />
                  <Skel className="h-6 w-32" />
                </div>
              ) : (
                <div className="flex flex-wrap items-center gap-x-4 gap-y-2">
                  <StatusPill status={status} />

                  {periodEnd && (
                    <span className="inline-flex items-center gap-1.5 text-xs text-gray-500 font-medium">
                      <Clock className="w-3 h-3 text-gray-400" />
                      Renews {fmtDate(periodEnd)}
                    </span>
                  )}

                  {createdAt && (
                    <span className="inline-flex items-center gap-1.5 text-xs text-gray-400">
                      <Calendar className="w-3 h-3" />
                      Member since {fmtMonthYear(createdAt)}
                    </span>
                  )}
                </div>
              )}
            </div>

            {/* Right — price display */}
            {!loading && (
              <div className="flex-shrink-0 sm:text-right">
                {plan === 'free' ? (
                  <div>
                    <p className="text-4xl font-bold text-gray-900">£0</p>
                    <p className="text-xs text-gray-400 mt-1">No credit card required</p>
                  </div>
                ) : plan === 'enterprise' ? (
                  <div>
                    <p className="text-2xl font-bold text-gray-900">Custom</p>
                    <p className="text-xs text-gray-400 mt-1">Contact your account manager</p>
                  </div>
                ) : (
                  <div>
                    <div className="flex items-end gap-1.5 sm:justify-end">
                      <span className="text-4xl font-bold text-gray-900 tabular-nums">
                        £{price}
                      </span>
                      <span className="text-sm text-gray-400 mb-1">/mo</span>
                    </div>
                    {billingInterval === 'annual' && planMeta.annualSave > 0 && (
                      <div className="mt-2 inline-flex items-center gap-1 px-2.5 py-1 rounded-full bg-green-50 border border-green-100 text-[10px] font-bold text-green-700 uppercase tracking-wider">
                        <TrendingUp className="w-3 h-3" />
                        Saving £{planMeta.annualSave}/yr
                      </div>
                    )}
                    {billingInterval === 'monthly' && planMeta.annualSave > 0 && (
                      <p className="mt-1.5 text-[11px] text-gray-400 sm:text-right">
                        Save £{planMeta.annualSave}/yr with annual
                      </p>
                    )}
                  </div>
                )}
              </div>
            )}
          </div>
        </div>

        {/* Action bar */}
        <div className="flex flex-wrap items-center gap-2.5 px-7 sm:px-8 py-4 bg-gray-50 border-t border-gray-100">
          {canUpgrade ? (
            <button
              onClick={() => handleUpgrade('professional')}
              className="btn-primary py-2 text-sm"
            >
              <Zap className="w-4 h-4" />
              Upgrade Plan
            </button>
          ) : (
            <button onClick={() => navigate('/pricing')} className="btn-secondary py-2 text-sm">
              <ArrowRight className="w-4 h-4" />
              Change Plan
            </button>
          )}

          <button
            onClick={handleManageSubscription}
            disabled={portalLoading}
            className="btn-secondary py-2 text-sm"
          >
            <CreditCard className="w-4 h-4" />
            Manage Payment
          </button>

          <button
            onClick={() => setBillingInterval(v => v === 'monthly' ? 'annual' : 'monthly')}
            className="btn-secondary py-2 text-sm"
          >
            <RefreshCw className="w-4 h-4" />
            {billingInterval === 'monthly' ? 'Switch to Annual' : 'Switch to Monthly'}
          </button>

          <button
            onClick={handleManageSubscription}
            disabled={portalLoading}
            className="btn-secondary py-2 text-sm"
          >
            <CreditCard className="w-4 h-4" />
            {portalLoading ? 'Opening Portal…' : 'Manage Subscription'}
          </button>

          <button
            onClick={() => navigate('/pricing')}
            className="btn-ghost py-2 text-sm text-gray-500 hover:text-gray-700 hover:bg-white ml-auto"
          >
            View pricing
          </button>
        </div>
      </div>

      {/* ══════════════════════════════════════════════════════════════════ */}
      {/* SECTION 2 — Usage meters                                         */}
      {/* ══════════════════════════════════════════════════════════════════ */}
      <div className="mb-6">
        <SectionLabel>Plan Usage</SectionLabel>
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-3 sm:gap-4">
          {loading
            ? Array.from({ length: 4 }).map((_, i) => <Skel key={i} className="h-[116px]" />)
            : (
              <>
                <UsageCard
                  icon={Globe}
                  label="Domains"
                  used={usage.domains ?? 0}
                  limit={lims.domains}
                />
                <UsageCard
                  icon={Users}
                  label="Users"
                  used={usage.users ?? 0}
                  limit={lims.users}
                />
                <UsageCard
                  icon={Calendar}
                  label="Scheduled Scans"
                  used={usage.scheduled_scans ?? 0}
                  limit={lims.scheduled_scans}
                />
                <UsageCard
                  icon={FileBarChart2}
                  label="Reports"
                  used={usage.reports ?? 0}
                  limit={lims.reports}
                />
              </>
            )
          }
        </div>
      </div>

      {/* ══════════════════════════════════════════════════════════════════ */}
      {/* SECTION 3 — Plan comparison + Quick actions                      */}
      {/* ══════════════════════════════════════════════════════════════════ */}
      <div className="grid lg:grid-cols-3 gap-5 mb-6">

        {/* Plan comparison — 2 columns */}
        <div className="lg:col-span-2">
          <div className="flex items-center justify-between mb-3 px-0.5">
            <SectionLabel>All Plans</SectionLabel>

            {/* Billing interval toggle */}
            <div className="flex items-center gap-0.5 p-0.5 bg-gray-100 rounded-xl mb-3">
              {[
                { key: 'monthly', label: 'Monthly' },
                { key: 'annual',  label: 'Annual −20%' },
              ].map(({ key, label }) => (
                <button
                  key={key}
                  onClick={() => setBillingInterval(key)}
                  className={`
                    px-3 py-1.5 rounded-[10px] text-[11px] font-semibold transition-all duration-150
                    ${billingInterval === key
                      ? 'bg-white text-gray-900 shadow-sm border border-gray-200'
                      : 'text-gray-500 hover:text-gray-700'}
                  `}
                >
                  {label}
                </button>
              ))}
            </div>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
            {['starter', 'professional', 'business'].map(p => (
              <PlanCard
                key={p}
                planKey={p}
                currentPlan={plan}
                interval={billingInterval}
                onUpgrade={handleUpgrade}
              />
            ))}
          </div>
        </div>

        {/* Quick actions — 1 column */}
        <div>
          <SectionLabel>Manage Subscription</SectionLabel>
          <div className="bg-white rounded-2xl border border-gray-100 shadow-card p-2">
            <ActionRow
              icon={Zap}
              label="Upgrade Plan"
              desc="Unlock more workspaces and capacity"
              onClick={() => handleUpgrade('professional')}
            />
            <ActionRow
              icon={RefreshCw}
              label="Change Billing Cycle"
              desc="Switch between monthly and annual"
            />
            <ActionRow
              icon={CreditCard}
              label="Payment Method"
              desc="Update your saved card"
              onClick={handleManageSubscription}
            />
            <ActionRow
              icon={Building2}
              label="Billing Details"
              desc="Company name, address, VAT"
              onClick={handleManageSubscription}
            />
            <ActionRow
              icon={FileText}
              label="View Invoices"
              desc="Download past receipts"
              onClick={handleManageSubscription}
            />
            <div className="my-1 mx-2 border-t border-gray-100" />
            <ActionRow
              icon={AlertTriangle}
              label="Cancel Subscription"
              danger
              onClick={handleManageSubscription}
            />
          </div>

          {/* Trust indicators */}
          <div className="mt-4 flex flex-col gap-1.5 px-1">
            {[
              { icon: Shield,     text: 'Secured by Stripe'  },
              { icon: Check,      text: 'Cancel any time'    },
              { icon: CreditCard, text: 'No hidden fees'     },
            ].map(({ icon: Icon, text }) => (
              <span key={text} className="flex items-center gap-2 text-[11px] text-gray-400 font-medium">
                <Icon className="w-3.5 h-3.5 text-brand-400 flex-shrink-0" />
                {text}
              </span>
            ))}
          </div>
        </div>
      </div>

      {/* ══════════════════════════════════════════════════════════════════ */}
      {/* SECTION 4 — Billing history                                      */}
      {/* ══════════════════════════════════════════════════════════════════ */}
      <div className="bg-white rounded-2xl border border-gray-100 shadow-card overflow-hidden">

        {/* Table header */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-gray-100">
          <div>
            <h2 className="text-sm font-bold text-gray-900">Billing History</h2>
            <p className="text-[11px] text-gray-400 mt-0.5">Download your past invoices</p>
          </div>
          {invoices.length > 0 && (
            <button className="btn-ghost text-xs py-1.5">
              <Download className="w-3.5 h-3.5" />
              Export all
            </button>
          )}
        </div>

        {/* Empty state or table */}
        {invoices.length === 0 ? (
          <EmptyInvoices />
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full data-table">
              <thead>
                <tr>
                  <th>Invoice</th>
                  <th>Date</th>
                  <th>Amount</th>
                  <th>Status</th>
                  <th className="text-right pr-5">Actions</th>
                </tr>
              </thead>
              <tbody>
                {invoices.map(inv => (
                  <tr key={inv.id} className="hover:bg-gray-50/60 transition-colors">
                    <td className="font-mono text-xs text-gray-500">{inv.id}</td>
                    <td className="text-gray-600 text-sm">{fmtDate(inv.date)}</td>
                    <td className="font-semibold text-gray-900 tabular-nums text-sm">
                      £{inv.amount.toFixed(2)}
                    </td>
                    <td>
                      <span className={`
                        inline-flex items-center gap-1 px-2 py-0.5 rounded-full border text-xs font-semibold
                        ${inv.status === 'paid'
                          ? 'bg-green-50 text-green-700 border-green-100'
                          : 'bg-amber-50 text-amber-700 border-amber-100'}
                      `}>
                        <span className={`w-1.5 h-1.5 rounded-full ${inv.status === 'paid' ? 'bg-green-400' : 'bg-amber-400'}`} />
                        {inv.status === 'paid' ? 'Paid' : 'Pending'}
                      </span>
                    </td>
                    <td className="text-right pr-5">
                      <button className="btn-ghost py-1 text-xs">
                        <Download className="w-3 h-3" />
                        PDF
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* ── Footer spacer ────────────────────────────────────────────────── */}
      <div className="h-8" />
    </div>
  )
}
