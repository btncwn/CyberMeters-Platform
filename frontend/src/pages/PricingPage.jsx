import { useEffect, useMemo, useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { Check, ArrowRight, Loader2 } from 'lucide-react'
import CyberMetersLogo from '../components/CyberMetersLogo'
import { api } from '../api'
import { useAuth } from '../context/AuthContext'

const FALLBACK_PLANS = [
  {
    key: 'free',
    name: 'Free',
    description: 'Evaluate CyberMeters with basic scans and on-screen results.',
    monthly_gbp: 0,
    annual_gbp: 0,
    checkout_enabled: false,
    features: ['Basic scans', 'Basic reports', '1 workspace'],
  },
  {
    key: 'starter',
    name: 'Starter',
    description: 'Scheduled scans and starter executive reporting.',
    monthly_gbp: 29,
    annual_gbp: 276,
    checkout_enabled: true,
    features: ['3 workspaces', '10 domains', 'Scheduled scans'],
  },
  {
    key: 'professional',
    name: 'Professional',
    description: 'Business risk, Cyber Essentials readiness, and vendor risk.',
    monthly_gbp: 149,
    annual_gbp: 1428,
    checkout_enabled: true,
    features: ['Business Risk Score', 'Cyber Essentials Readiness', 'Vendor Risk'],
  },
  {
    key: 'business',
    name: 'Business',
    description: 'Portfolio monitoring, white-label reports, and extended retention.',
    monthly_gbp: 399,
    annual_gbp: 3828,
    checkout_enabled: true,
    features: ['Portfolio Monitoring', 'White-label reports', 'Extended retention'],
  },
  {
    key: 'enterprise',
    name: 'Enterprise',
    description: 'MSP dashboard, custom limits, priority support, and onboarding.',
    monthly_gbp: null,
    annual_gbp: null,
    checkout_enabled: false,
    features: ['MSP Dashboard', 'Custom limits', 'Priority support'],
  },
]

function formatLimit(value) {
  if (value === undefined || value === null) return null
  if (value >= 999999) return 'Unlimited'
  return value
}

function planFeatures(plan) {
  const limits = plan.limits || {}
  const fromLimits = [
    formatLimit(limits.workspaces) && `${formatLimit(limits.workspaces)} workspace${limits.workspaces === 1 ? '' : 's'}`,
    formatLimit(limits.domains) && `${formatLimit(limits.domains)} domain${limits.domains === 1 ? '' : 's'}`,
    formatLimit(limits.users) && `${formatLimit(limits.users)} user${limits.users === 1 ? '' : 's'}`,
    formatLimit(limits.scans_per_month) && `${formatLimit(limits.scans_per_month)} scans/month`,
    formatLimit(limits.reports_per_month) && `${formatLimit(limits.reports_per_month)} reports/month`,
  ].filter(Boolean)

  if (fromLimits.length > 0) return fromLimits.slice(0, 5)
  return plan.features || []
}

function priceFor(plan, interval) {
  if (plan.key === 'enterprise') return 'Custom'
  if (interval === 'annual' && Number.isFinite(plan.annual_gbp)) {
    return `£${plan.annual_gbp}/yr`
  }
  if (Number.isFinite(plan.monthly_gbp)) {
    return `£${plan.monthly_gbp}/mo`
  }
  return 'Contact sales'
}

export default function PricingPage() {
  const navigate = useNavigate()
  const { isAuthenticated } = useAuth()
  const [plans, setPlans] = useState(FALLBACK_PLANS)
  const [interval, setInterval] = useState('monthly')
  const [loading, setLoading] = useState(true)
  const [checkoutPlan, setCheckoutPlan] = useState(null)
  const [error, setError] = useState(null)

  useEffect(() => {
    let cancelled = false
    async function load() {
      try {
        const data = await api.getBillingPlans()
        if (!cancelled && Array.isArray(data?.plans) && data.plans.length > 0) {
          setPlans(data.plans)
        }
      } catch {
        // Fallback copy keeps the pricing page available if billing metadata is unreachable.
      } finally {
        if (!cancelled) setLoading(false)
      }
    }
    load()
    return () => { cancelled = true }
  }, [])

  const orderedPlans = useMemo(() => {
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
      window.location.href = 'mailto:hello@cybermeters.com?subject=CyberMeters%20Enterprise'
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
      <header className="bg-white border-b border-gray-100">
        <div className="max-w-6xl mx-auto px-6 h-16 flex items-center justify-between">
          <Link to={isAuthenticated ? '/dashboard' : '/login'}>
            <CyberMetersLogo size={28} showWordmark animated />
          </Link>
          <nav className="flex items-center gap-4 text-sm font-medium">
            <Link to="/support" className="text-gray-500 hover:text-gray-800">Support</Link>
            <Link to={isAuthenticated ? '/dashboard' : '/login'} className="btn-secondary py-2">
              {isAuthenticated ? 'Dashboard' : 'Sign in'}
            </Link>
          </nav>
        </div>
      </header>

      <main className="max-w-6xl mx-auto px-6 py-12">
        <div className="max-w-2xl mb-8">
          <p className="text-xs font-bold uppercase tracking-widest text-brand-600 mb-3">Pricing</p>
          <h1 className="text-4xl font-bold text-gray-900 tracking-tight">Choose the plan that matches your security workflow.</h1>
          <p className="text-gray-500 mt-4">
            Start with external attack surface monitoring, then add executive reporting, vendor risk, and MSP-ready capabilities as you grow.
          </p>
        </div>

        <div className="flex items-center gap-2 mb-6">
          {['monthly', 'annual'].map(key => (
            <button
              key={key}
              onClick={() => setInterval(key)}
              className={`px-4 py-2 rounded-xl text-sm font-semibold border ${
                interval === key
                  ? 'bg-white text-gray-900 border-gray-200 shadow-sm'
                  : 'bg-transparent text-gray-500 border-transparent hover:bg-white'
              }`}
            >
              {key === 'monthly' ? 'Monthly' : 'Annual'}
            </button>
          ))}
          {loading && <span className="text-xs text-gray-400 ml-2">Loading live plan metadata…</span>}
        </div>

        {error && (
          <div className="mb-6 rounded-xl border border-red-100 bg-red-50 px-4 py-3 text-sm text-red-700">
            {error}
          </div>
        )}

        <div className="grid md:grid-cols-2 xl:grid-cols-5 gap-4">
          {orderedPlans.map(plan => (
            <section key={plan.key} className="bg-white border border-gray-100 rounded-2xl shadow-card p-5 flex flex-col">
              <div>
                <h2 className="text-lg font-bold text-gray-900">{plan.name || plan.key}</h2>
                <p className="text-sm text-gray-500 mt-2 min-h-[60px]">{plan.description}</p>
                <div className="mt-5">
                  <span className="text-3xl font-bold text-gray-900">{priceFor(plan, interval)}</span>
                </div>
              </div>

              <ul className="mt-5 space-y-2 flex-1">
                {planFeatures(plan).map(feature => (
                  <li key={feature} className="flex items-start gap-2 text-sm text-gray-600">
                    <Check className="w-4 h-4 text-brand-600 mt-0.5 flex-shrink-0" />
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
                  <>
                    {plan.key === 'free' ? 'Start Free' : plan.key === 'enterprise' ? 'Contact Sales' : 'Start Checkout'}
                    <ArrowRight className="w-4 h-4" />
                  </>
                )}
              </button>
            </section>
          ))}
        </div>

        <footer className="mt-12 pt-6 border-t border-gray-200 flex flex-wrap gap-4 text-sm text-gray-400">
          <Link to="/terms" className="hover:text-gray-700">Terms</Link>
          <Link to="/privacy" className="hover:text-gray-700">Privacy</Link>
          <Link to="/support" className="hover:text-gray-700">Support</Link>
        </footer>
      </main>
    </div>
  )
}
