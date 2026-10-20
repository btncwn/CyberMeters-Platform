import { useCallback, useEffect, useMemo, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { Loader2 } from 'lucide-react'
import PublicSiteHeader from '../components/PublicSiteHeader'
import PublicSiteFooter from '../components/PublicSiteFooter'
import { api } from '../api'
import { useAuth } from '../context/AuthContext'

// Pricing is served EXCLUSIVELY by the canonical plan API (backed by the
// locked pricing policy). There is deliberately no hard-coded price fallback:
// if live plan metadata is unreachable the page says so honestly instead of
// silently advertising a stale ladder the backend would refuse to charge.

function gbp(value) {
  if (value === null || value === undefined || !Number.isFinite(value)) return null
  return `£${value.toFixed(2).replace(/\.00$/, '')}`
}

// Customer-facing value metric is monitored domains (product rule). Workspaces,
// users and internal scan/report quotas are enforcement concepts and never
// appear on pricing cards. MSP is presented separately and sales-led —
// Business is an SMB plan, not an MSP plan.
// What a plan leaves out, read from the plan API's own feature lists
// (PLAN_FEATURES) against Professional, so the card can never promise a
// feature the plan does not grant (founder, 20 Oct 2026). Only the features a
// small business would look for are named.
const NOTABLE_FEATURES = [
  ['executive_dashboard', 'Executive dashboard'],
  ['audit_logs', 'audit log'],
  ['vendor_risk', 'third-party services view'],
]

export function notIncluded(plan, plans) {
  const reference = (plans || []).find((p) => p.key === 'professional')
  if (!Array.isArray(plan?.features) || !Array.isArray(reference?.features) || plan.key === 'free' || plan.key === 'enterprise') return []
  return NOTABLE_FEATURES
    .filter(([key]) => reference.features.includes(key) && !plan.features.includes(key))
    .map(([, label]) => label)
}

function planFeatures(plan, plans) {
  const pm = plan.pricing_model || {}
  const features = []
  if (plan.key === 'enterprise') {
    features.push('Built for MSPs and advisors managing client portfolios')
    if (pm.per_domain_monthly_gbp != null && pm.min_billed_domains != null) {
      features.push(`Base fee + ${gbp(pm.per_domain_monthly_gbp)}/month per monitored domain (minimum ${pm.min_billed_domains} domains)`)
    }
    return features
  }
  const domains = pm.included_domains ?? plan.limits?.domains
  if (domains != null) {
    features.push(domains === 1 ? '1 monitored domain' : `${domains} monitored domains included`)
  }
  const missing = notIncluded(plan, plans)
  if (missing.length) {
    features.push(`Not included: ${missing.join(', ')}`)
  }
  if (plan.key === 'free' && pm.trial) {
    features.push(`Full product for ${pm.trial.duration_days} days`)
    if (pm.trial.card_required === false) features.push('No card required')
  }
  return features
}

function priceFor(plan, interval) {
  if (plan.key === 'enterprise') {
    const pm = plan.pricing_model || {}
    const floor = interval === 'annual' ? pm.floor_annual_gbp : pm.floor_monthly_gbp
    if (floor != null) return `from ${gbp(floor)}${interval === 'annual' ? '/yr' : '/mo'}`
    return 'Contact sales'
  }
  if (interval === 'annual' && Number.isFinite(plan.annual_gbp)) {
    return `${gbp(plan.annual_gbp)}/yr`
  }
  if (Number.isFinite(plan.monthly_gbp)) {
    return plan.monthly_gbp === 0 ? '£0' : `${gbp(plan.monthly_gbp)}/mo`
  }
  return 'Contact sales'
}

export default function PricingPage() {
  const navigate = useNavigate()
  const { isAuthenticated } = useAuth()
  const [plans, setPlans] = useState(null)
  const [interval, setInterval] = useState(() => {
    // Persist the billing-cycle choice so it survives the signup/checkout round-trip.
    try {
      return localStorage.getItem('cm_billing_interval') === 'annual' ? 'annual' : 'monthly'
    } catch {
      return 'monthly'
    }
  })
  const [loading, setLoading] = useState(true)
  const [loadError, setLoadError] = useState(false)
  const [checkoutPlan, setCheckoutPlan] = useState(null)
  const [error, setError] = useState(null)

  const load = useCallback(async () => {
    setLoading(true)
    setLoadError(false)
    try {
      const data = await api.getBillingPlans()
      if (Array.isArray(data?.plans) && data.plans.length > 0) {
        setPlans(data.plans)
      } else {
        setLoadError(true)
      }
    } catch {
      // Fail honestly: no stale fallback prices are ever shown.
      setLoadError(true)
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => { load() }, [load])

  const orderedPlans = useMemo(() => {
    if (!plans) return []
    const order = ['free', 'starter', 'professional', 'business', 'enterprise']
    return [...plans].sort((a, b) => order.indexOf(a.key) - order.indexOf(b.key))
  }, [plans])

  async function startCheckout(plan) {
    setError(null)
    if (plan.key === 'free') {
      navigate(isAuthenticated ? '/dashboard' : '/signup')
      return
    }
    if (plan.key === 'enterprise' || !plan.checkout_enabled) {
      window.location.href = 'mailto:hello@cybermeters.com?subject=CyberMeters%20MSP'
      return
    }
    if (!isAuthenticated) {
      navigate('/signup', { state: { from: { pathname: '/pricing' } } })
      return
    }

    setCheckoutPlan(plan.key)
    try {
      const origin = window.location.origin
      const res = await api.startCheckout(
        plan.key,
        interval,
        `${origin}/checkout/success`,
        `${origin}/checkout/cancel`,
      )
      if (res?.checkout_url) {
        window.location.href = res.checkout_url
        return
      }
      throw new Error('Checkout URL was not returned')
    } catch (e) {
      setError(e?.message || 'Checkout could not be started')
    } finally {
      setCheckoutPlan(null)
    }
  }

  return (
    <div className="min-h-screen bg-gray-50">
      <PublicSiteHeader signedIn={isAuthenticated} />

      <main className="max-w-6xl mx-auto px-6 py-12">
        <div className="max-w-2xl mb-8">
          <p className="text-xs font-bold uppercase tracking-widest text-brand-700 mb-3">Pricing</p>
          <h1 className="text-4xl font-bold text-gray-900 tracking-tight">Choose the plan that matches your security workflow.</h1>
          <p className="text-gray-500 mt-4">
            Every paid plan is the full Cyber MOT — your whole external posture, alerts, managed cases,
            reports and remediation. Pricing is per monitored domain, starting with a 14-day full trial.
          </p>
        </div>

        <div className="flex items-center gap-2 mb-6">
          {['monthly', 'annual'].map(key => (
            <button
              key={key}
              onClick={() => {
                setInterval(key)
                try { localStorage.setItem('cm_billing_interval', key) } catch { /* storage unavailable — ignore */ }
              }}
              className={`px-4 py-2 rounded-xl text-sm font-semibold border ${
                interval === key
                  ? 'bg-white text-gray-900 border-gray-200 shadow-xs'
                  : 'bg-transparent text-gray-500 border-transparent hover:bg-white'
              }`}
            >
              {key === 'monthly' ? 'Monthly' : 'Annual'}
            </button>
          ))}
          {/* Annual = pay for 10 months, receive 12 (exact policy figures; checkout
              refuses any Stripe price that does not charge them). */}
          <span className="text-xs text-gray-400 ml-1">Annual billing: 2 months free.</span>
          {loading && <span className="text-xs text-gray-400 ml-2">Loading live pricing…</span>}
        </div>

        {error && (
          <div className="mb-6 rounded-xl border border-red-100 bg-red-50 px-4 py-3 text-sm text-red-700">
            {error}
          </div>
        )}

        {loadError && !loading && (
          <div className="rounded-2xl border border-[1.5px] border-brand-700 bg-transparent px-6 py-8 text-center">
            <p className="text-sm font-semibold text-brand-700 mb-1">Live pricing is temporarily unavailable</p>
            <p className="text-sm text-brand-700 mb-4">
              We only show prices confirmed by our billing system, so nothing is displayed right now.
              Please try again in a moment.
            </p>
            <button onClick={load} className="inline-flex items-center gap-2 btn-secondary py-2">
              Retry
            </button>
          </div>
        )}

        {!loadError && !loading && (
          <div className="grid md:grid-cols-2 xl:grid-cols-5 gap-4">
            {orderedPlans.map(plan => (
              <section
                key={plan.key}
                className={`bg-white rounded-2xl shadow-card p-5 flex flex-col ${
                  plan.key === 'professional'
                    ? 'relative border border-brand-500 ring-1 ring-brand-500'
                    : 'border border-gray-100'
                }`}
              >
                {plan.key === 'professional' && (
                  <span className="absolute -top-3 left-5 inline-flex items-center rounded-full bg-brand-200 px-3 py-1 text-xs font-semibold text-brand-900 shadow-xs">
                    Most popular
                  </span>
                )}
                <div>
                  <h2 className="text-lg font-bold text-gray-900">{plan.name || plan.key}</h2>
                  <p className="text-sm text-gray-600 mt-2 min-h-[60px] font-medium">{plan.description}</p>
                  <div className="mt-5">
                    <span className="text-3xl font-bold text-gray-900">{priceFor(plan, interval)}</span>
                  </div>
                </div>

                <ul className="mt-5 list-disc pl-5 space-y-2 flex-1">
                  {planFeatures(plan, orderedPlans).map(feature => (
                    <li key={feature} className="text-sm text-gray-600">
                      <span>{feature}</span>
                    </li>
                  ))}
                </ul>

                <button
                  onClick={() => startCheckout(plan)}
                  disabled={checkoutPlan === plan.key}
                  className={`mt-6 w-full ${plan.key === 'professional' ? 'btn-primary' : 'btn-secondary'} justify-center py-2.5`}
                >
                  {checkoutPlan === plan.key ? (
                    <Loader2 className="w-4 h-4 animate-spin" />
                  ) : (
                    plan.key === 'free' ? 'Start free trial' : plan.key === 'enterprise' ? 'Contact Sales' : 'Start Checkout'
                  )}
                </button>
              </section>
            ))}
          </div>
        )}

      </main>
      <PublicSiteFooter />
    </div>
  )
}
