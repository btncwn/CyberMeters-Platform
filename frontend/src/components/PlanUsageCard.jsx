/**
 * PlanUsageCard — reusable plan + usage display component.
 *
 * Exports:
 *   PlanUsageCard  — compact card showing current plan and key usage meters.
 *                    Drop in on any page where quota context is helpful.
 *   PlanGate       — full-page lock state for premium features. Renders a
 *                    friendly "Upgrade Required" screen when the API returns
 *                    403 { error: 'plan_feature_required' }. Pass it the
 *                    error object and your normal page children; it selects
 *                    the right view automatically.
 *
 * Usage — PlanGate wrapping a page body:
 *
 *   import { PlanGate } from '../../components/PlanUsageCard'
 *
 *   function MyPage() {
 *     const [data, setData] = useState(null)
 *     const [err,  setErr]  = useState(null)
 *     // ... fetch, catch err, call setErr(err)
 *     return (
 *       <WsPage ...>
 *         <PlanGate error={err}>
 *           <YourNormalContent data={data} />
 *         </PlanGate>
 *       </WsPage>
 *     )
 *   }
 *
 * The API must return { error: 'plan_feature_required', required_plan: 'professional', ... }
 * for PlanGate to render the upgrade wall. Any other error falls through.
 */

import { Lock, Zap, ArrowRight, TrendingUp, FileText, Globe } from 'lucide-react'
import { useNavigate } from 'react-router-dom'

// ── Plan display config ──────────────────────────────────────────────────────

const PLAN_CFG = {
  free:         { label: 'Free',         bg: 'bg-gray-100',   text: 'text-gray-600',   border: 'border-gray-200'  },
  starter:      { label: 'Starter',      bg: 'bg-blue-50',    text: 'text-blue-700',   border: 'border-blue-200'  },
  professional: { label: 'Professional', bg: 'bg-brand-50',   text: 'text-brand-700',  border: 'border-brand-200' },
  business:     { label: 'Business',     bg: 'bg-purple-50',  text: 'text-purple-700', border: 'border-purple-200'},
  enterprise:   { label: 'MSP',          bg: 'bg-amber-50',   text: 'text-amber-700',  border: 'border-amber-200' },
}

const PLAN_ORDER = ['free', 'starter', 'professional', 'business', 'enterprise']

// Human-readable feature names for the upgrade wall
const FEATURE_LABELS = {
  business_risk_score: 'Business Risk Score',
  cyber_essentials:    'Cyber Essentials Readiness',
  vendor_risk:         'Vendor & Supply Chain Risk',
  portfolio_monitoring:'Portfolio Risk Monitoring',
  white_label:         'White Label Reports',
  msp_dashboard:       'MSP Dashboard',
}

// What each required plan unlocks (shown in the upgrade CTA).
// Domain allowances MUST match the locked canonical ladder (Starter 1 /
// Professional 3 / Business 10 included) in docs/PRICING-POLICY.md — this card
// is an upgrade wall, so wrong numbers are mis-selling.
const PLAN_FEATURES = {
  starter:      ['Business Risk Score', 'Executive PDF Reports', '1 monitored domain'],
  professional: ['Cyber Essentials Readiness', 'Vendor Risk Analysis', 'Supply Chain Intelligence', 'Up to 3 monitored domains'],
  business:     ['Portfolio Risk Monitoring', 'White Label Reports', '10 monitored domains included'],
  enterprise:   ['MSP Dashboard', 'Built for client portfolios', 'Dedicated support'],
}

// ── PlanBadge ────────────────────────────────────────────────────────────────

export function PlanBadge({ plan }) {
  const cfg = PLAN_CFG[plan] ?? PLAN_CFG.free
  return (
    <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full border text-xs font-semibold ${cfg.bg} ${cfg.text} ${cfg.border}`}>
      {cfg.label}
    </span>
  )
}

// ── UsageBar ─────────────────────────────────────────────────────────────────

function UsageBar({ icon: Icon, label, used, limit, note }) {
  const infinite = limit >= 999999
  const pct      = infinite ? 0 : limit > 0 ? Math.min(100, Math.round((used / limit) * 100)) : 0
  const near     = pct >= 80
  const full     = pct >= 100
  const barColor = full ? 'bg-red-500' : near ? 'bg-amber-400' : 'bg-brand-500'

  return (
    <div className="py-2.5 border-b border-gray-50 last:border-0">
      <div className="flex items-center justify-between mb-1.5">
        <span className="flex items-center gap-1.5 text-xs text-gray-600">
          {Icon && <Icon className="w-3 h-3 text-gray-400" />}
          {label}
          {note && <span className="text-gray-400">{note}</span>}
        </span>
        <span className={`text-xs font-semibold ${full ? 'text-red-600' : near ? 'text-amber-600' : 'text-gray-500'}`}>
          {used} / {infinite ? '∞' : limit}
        </span>
      </div>
      {!infinite && (
        <div className="h-1 bg-gray-100 rounded-full overflow-hidden">
          <div className={`h-full rounded-full transition-all ${barColor}`} style={{ width: `${pct}%` }} />
        </div>
      )}
    </div>
  )
}

// ── PlanUsageCard ─────────────────────────────────────────────────────────────

/**
 * Compact plan + usage card. Pass `planLimits` from
 * api.getSubscriptionLimits() → { plan, limits, usage }.
 *
 * If planLimits is null/undefined renders nothing (safe to render always).
 */
export function PlanUsageCard({ planLimits, className = '' }) {
  const navigate = useNavigate()
  if (!planLimits) return null

  const { plan, limits = {}, usage = {} } = planLimits
  const cfg = PLAN_CFG[plan] ?? PLAN_CFG.free
  const showUpgrade = plan === 'free' || plan === 'starter'

  return (
    <div className={`card ${className}`}>
      {/* Header */}
      <div className="flex items-center justify-between mb-4 pb-3 border-b border-gray-100">
        <div className="flex items-center gap-2">
          <Zap className="w-4 h-4 text-brand-500" />
          <span className="text-sm font-semibold text-gray-900">Plan Usage</span>
        </div>
        <PlanBadge plan={plan} />
      </div>

      {/* Usage meters */}
      <UsageBar
        icon={Globe}
        label="Workspaces"
        used={usage.workspaces ?? 0}
        limit={limits.workspaces ?? 1}
      />
      <UsageBar
        icon={TrendingUp}
        label="Scans this month"
        used={usage.scans_this_month ?? 0}
        limit={limits.scans_per_month ?? 5}
      />
      <UsageBar
        icon={FileText}
        label="Reports this month"
        used={usage.reports_this_month ?? 0}
        limit={limits.reports_per_month ?? 3}
      />

      {/* Upgrade nudge */}
      {showUpgrade && (
        <button
          onClick={() => navigate('/billing')}
          className="mt-4 w-full flex items-center justify-between px-3 py-2 rounded-lg bg-brand-50 hover:bg-brand-100 transition-colors group"
        >
          <span className="text-xs font-semibold text-brand-700">Upgrade your plan</span>
          <ArrowRight className="w-3.5 h-3.5 text-brand-500 group-hover:translate-x-0.5 transition-transform" />
        </button>
      )}
    </div>
  )
}

// ── PlanGate ──────────────────────────────────────────────────────────────────

/**
 * Wraps page content and renders an upgrade wall when the API returns a
 * plan_feature_required 403.
 *
 * Props:
 *   error     — the caught error object (or null). Must have
 *               error.code === 'plan_feature_required' (set by the API)
 *               or error.error === 'plan_feature_required' for the gate to trigger.
 *   children  — normal page content shown when not gated.
 *   feature   — optional feature key override (detected from error automatically).
 *   requiredPlan — optional plan name override.
 */
export function PlanGate({ error, children, feature: featureOverride, requiredPlan: planOverride }) {
  const navigate = useNavigate()

  // Detect gate trigger — support both thrown Error objects and parsed API bodies
  const apiError = error?.error ?? error?.code ?? ''
  const isGated  = apiError === 'plan_feature_required'

  if (!isGated) return children

  const featureKey   = featureOverride ?? error?.feature ?? ''
  const requiredPlan = planOverride ?? error?.required_plan ?? 'starter'
  const featureLabel = FEATURE_LABELS[featureKey] ?? 'This feature'
  const planCfg      = PLAN_CFG[requiredPlan] ?? PLAN_CFG.starter
  const planFeatures = PLAN_FEATURES[requiredPlan] ?? []

  // Ordered plan index for "plans above" display
  const planIdx  = PLAN_ORDER.indexOf(requiredPlan)
  const abovePlans = PLAN_ORDER.slice(planIdx).filter(p => p !== 'free')

  return (
    <div className="flex items-start justify-center min-h-[55vh] pt-16">
      <div className="max-w-md w-full text-center">
        {/* Lock icon */}
        <div className="w-16 h-16 rounded-2xl bg-gray-50 border border-gray-200 flex items-center justify-center mx-auto mb-6">
          <Lock className="w-7 h-7 text-gray-400" />
        </div>

        {/* Heading */}
        <h2 className="text-xl font-bold text-gray-900 mb-2">
          {featureLabel} requires an upgrade
        </h2>
        <p className="text-sm text-gray-500 mb-6">
          This feature is available on the{' '}
          <span className={`font-semibold ${planCfg.text}`}>{planCfg.label}</span>
          {abovePlans.length > 1 ? ' plan and above' : ' plan'}.
        </p>

        {/* Feature list */}
        {planFeatures.length > 0 && (
          <div className={`rounded-xl border ${planCfg.border} ${planCfg.bg} px-5 py-4 mb-6 text-left`}>
            <p className={`text-xs font-semibold uppercase tracking-wider mb-3 ${planCfg.text}`}>
              {planCfg.label} includes
            </p>
            <ul className="space-y-2">
              {planFeatures.map(f => (
                <li key={f} className="flex items-center gap-2 text-sm text-gray-700">
                  <span className={`w-1.5 h-1.5 rounded-full flex-shrink-0 ${planCfg.text.replace('text-', 'bg-')}`} />
                  {f}
                </li>
              ))}
            </ul>
          </div>
        )}

        {/* CTA */}
        <button
          onClick={() => navigate('/billing')}
          className="btn-primary w-full flex items-center justify-center gap-2 mb-3"
        >
          <Zap className="w-4 h-4" />
          Upgrade to {planCfg.label}
        </button>
        <button
          onClick={() => navigate(-1)}
          className="btn-secondary w-full"
        >
          Go back
        </button>
      </div>
    </div>
  )
}
