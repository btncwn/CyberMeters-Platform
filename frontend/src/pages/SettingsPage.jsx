import { useEffect, useState, useCallback } from 'react'
import {
  AlertTriangle, Building2, CheckCircle, CreditCard,
  Save, Settings, User, Bell,
} from 'lucide-react'
import { api } from '../api'
import { useAuth } from '../context/AuthContext'

const COMPANY_SIZES = ['', '1-10', '11-50', '51-200', '201-1000', '1000+']

function Field({ label, children, hint }) {
  return (
    <div>
      <label className="label mb-1.5 block">{label}</label>
      {children}
      {hint && <p className="text-xs text-gray-400 mt-1">{hint}</p>}
    </div>
  )
}

function Status({ error, ok }) {
  if (error) {
    return (
      <div className="flex items-center gap-2 px-3 py-2 rounded-xl bg-red-50 border border-red-100 text-xs text-red-600">
        <AlertTriangle className="w-4 h-4" />
        {error}
      </div>
    )
  }
  if (ok) {
    return (
      <div className="flex items-center gap-2 px-3 py-2 rounded-xl bg-green-50 border border-green-100 text-xs text-green-700">
        <CheckCircle className="w-4 h-4" />
        Saved
      </div>
    )
  }
  return null
}

function PlanBadge({ plan }) {
  return (
    <span className="inline-flex items-center px-2.5 py-1 rounded-full text-xs font-semibold bg-brand-50 text-brand-700 border border-brand-100 capitalize">
      {plan || 'free'}
    </span>
  )
}

function UsageLine({ label, used, limit }) {
  const unlimited = limit >= 999999
  const pct = unlimited || !limit ? 0 : Math.min(100, Math.round((used / limit) * 100))
  const full = !unlimited && pct >= 100
  const near = !unlimited && pct >= 80
  const color = full ? 'bg-red-500' : near ? 'bg-amber-400' : 'bg-brand-500'

  return (
    <div>
      <div className="flex items-center justify-between text-xs mb-1">
        <span className="text-gray-500">{label}</span>
        <span className={`font-semibold ${full ? 'text-red-600' : near ? 'text-amber-600' : 'text-gray-700'}`}>
          {used} / {unlimited ? '∞' : limit}
        </span>
      </div>
      {!unlimited && (
        <div className="h-1.5 rounded-full bg-gray-100 overflow-hidden">
          <div className={`h-full rounded-full ${color}`} style={{ width: `${pct}%` }} />
        </div>
      )}
    </div>
  )
}

// ── Notification Preferences Card ─────────────────────────────────────────────

const EMAIL_FREQUENCY_OPTIONS = [
  {
    value: 'all_alerts',
    label: 'All alerts',
    description: 'Email me for every critical and high severity finding.',
  },
  {
    value: 'critical_only',
    label: 'Critical only',
    description: 'Email me only for critical severity findings.',
  },
  {
    value: 'daily_digest',
    label: 'Daily digest',
    description: 'One summary email per day. No immediate alerts.',
  },
  {
    value: 'disabled',
    label: 'Disabled',
    description: 'No notification emails. In-app notifications still appear.',
  },
]

function NotificationPreferencesCard() {
  const wsId = localStorage.getItem('cybermeters_workspace_id')
  const [freq, setFreq]       = useState('all_alerts')
  const [loading, setLoading] = useState(false)
  const [saving,  setSaving]  = useState(false)
  const [status,  setStatus]  = useState({})

  const load = useCallback(async () => {
    if (!wsId) return
    setLoading(true)
    try {
      const data = await api.getNotificationPreferences(wsId)
      setFreq(data.email_frequency || 'all_alerts')
    } catch { /* silent — use default */ }
    finally { setLoading(false) }
  }, [wsId])

  useEffect(() => { load() }, [load])

  async function handleSave() {
    if (!wsId || saving) return
    setSaving(true)
    setStatus({})
    try {
      await api.updateNotificationPreferences(wsId, { email_frequency: freq })
      setStatus({ ok: true })
      setTimeout(() => setStatus({}), 3000)
    } catch (e) {
      setStatus({ error: e.message || 'Failed to save' })
    } finally {
      setSaving(false)
    }
  }

  if (!wsId) {
    return (
      <div className="card p-6 space-y-4 lg:col-span-2">
        <div className="flex items-center gap-2">
          <Bell className="w-4 h-4 text-brand-600" />
          <h2 className="text-sm font-bold text-gray-900">Notifications</h2>
        </div>
        <p className="text-sm text-gray-400">Select a workspace to configure notification preferences.</p>
      </div>
    )
  }

  return (
    <div className="card p-6 space-y-4 lg:col-span-2">
      <div className="flex items-center gap-2">
        <Bell className="w-4 h-4 text-brand-600" />
        <h2 className="text-sm font-bold text-gray-900">Notifications</h2>
      </div>

      <p className="text-xs text-gray-400">
        Control how often CyberMeters sends you email alerts for this workspace.
        In-app notifications always appear in the bell regardless of this setting.
      </p>

      {loading ? (
        <div className="py-4 text-center">
          <div className="w-5 h-5 border-2 border-brand-600 border-t-transparent rounded-full animate-spin mx-auto" />
        </div>
      ) : (
        <div className="space-y-2">
          {EMAIL_FREQUENCY_OPTIONS.map(opt => (
            <label
              key={opt.value}
              className={`flex items-start gap-3 p-3 rounded-xl border cursor-pointer transition-colors ${
                freq === opt.value
                  ? 'border-brand-300 bg-brand-50/40'
                  : 'border-gray-100 hover:border-gray-200 hover:bg-gray-50/50'
              }`}
            >
              <input
                type="radio"
                name="email_frequency"
                value={opt.value}
                checked={freq === opt.value}
                onChange={() => setFreq(opt.value)}
                className="mt-0.5 accent-brand-600 flex-shrink-0"
              />
              <div>
                <p className="text-sm font-semibold text-gray-800">{opt.label}</p>
                <p className="text-xs text-gray-400 mt-0.5">{opt.description}</p>
              </div>
            </label>
          ))}
        </div>
      )}

      <Status {...status} />

      <button
        type="button"
        onClick={handleSave}
        disabled={saving || loading}
        className="btn-primary disabled:opacity-50"
      >
        <Save className="w-4 h-4" />
        {saving ? 'Saving…' : 'Save Preferences'}
      </button>
    </div>
  )
}

export default function SettingsPage() {
  const { user, updateUser } = useAuth()
  const [loading, setLoading] = useState(true)
  const [loadError, setLoadError] = useState(null)
  const [account, setAccount] = useState({ name: '' })
  const [company, setCompany] = useState({
    company_name: '',
    website: '',
    industry: '',
    company_size: '',
    contact_name: '',
    contact_email: '',
  })
  const [subscription, setSubscription] = useState(null)
  const [usage, setUsage] = useState(null)
  const [accountSaving, setAccountSaving] = useState(false)
  const [companySaving, setCompanySaving] = useState(false)
  const [accountStatus, setAccountStatus] = useState({})
  const [companyStatus, setCompanyStatus] = useState({})

  useEffect(() => {
    let cancelled = false
    async function load() {
      setLoading(true)
      setLoadError(null)
      try {
        const [profileRes, companyRes, subscriptionRes, usageRes] = await Promise.all([
          api.getAccountProfile(),
          api.getCompanyProfile(),
          api.getSubscription(),
          api.getAccountUsage(),
        ])
        if (cancelled) return
        setAccount({ name: profileRes.user?.name || '' })
        const c = companyRes.company || profileRes.company || {}
        setCompany({
          company_name: c.company_name || '',
          website: c.website || '',
          industry: c.industry || '',
          company_size: c.company_size || '',
          contact_name: c.contact_name || '',
          contact_email: c.contact_email || '',
        })
        setSubscription(subscriptionRes.subscription || profileRes.subscription || null)
        setUsage(usageRes || null)
      } catch (e) {
        if (!cancelled) setLoadError(e.message)
      } finally {
        if (!cancelled) setLoading(false)
      }
    }
    load()
    return () => { cancelled = true }
  }, [])

  async function saveAccount(e) {
    e.preventDefault()
    setAccountSaving(true)
    setAccountStatus({})
    try {
      const res = await api.updateAccountProfile(account)
      updateUser(res.user)
      setAccount({ name: res.user?.name || '' })
      setAccountStatus({ ok: true })
    } catch (err) {
      setAccountStatus({ error: err.message })
    } finally {
      setAccountSaving(false)
    }
  }

  async function saveCompany(e) {
    e.preventDefault()
    setCompanySaving(true)
    setCompanyStatus({})
    try {
      const res = await api.updateCompanyProfile(company)
      const c = res.company || {}
      setCompany({
        company_name: c.company_name || '',
        website: c.website || '',
        industry: c.industry || '',
        company_size: c.company_size || '',
        contact_name: c.contact_name || '',
        contact_email: c.contact_email || '',
      })
      setCompanyStatus({ ok: true })
    } catch (err) {
      setCompanyStatus({ error: err.message })
    } finally {
      setCompanySaving(false)
    }
  }

  function updateCompanyField(e) {
    setCompanyStatus({})
    setCompany(prev => ({ ...prev, [e.target.name]: e.target.value }))
  }

  if (loading) {
    return (
      <div className="max-w-screen-xl mx-auto px-6 py-8">
        <div className="card p-12 text-center text-sm text-gray-400">Loading account settings...</div>
      </div>
    )
  }

  return (
    <div className="max-w-screen-xl mx-auto px-6 py-8">
      <div className="mb-8">
        <h1 className="text-2xl font-bold text-gray-900">Settings</h1>
        <p className="text-sm text-gray-400 mt-0.5">Account, company, and subscription details.</p>
      </div>

      {loadError && (
        <div className="mb-6 px-4 py-3 rounded-xl bg-red-50 border border-red-100 text-sm text-red-600">
          {loadError}
        </div>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <form onSubmit={saveAccount} className="card p-6 space-y-4">
          <div className="flex items-center gap-2">
            <User className="w-4 h-4 text-brand-600" />
            <h2 className="text-sm font-bold text-gray-900">Account Profile</h2>
          </div>
          <Field label="Name">
            <input
              className="input"
              value={account.name}
              onChange={e => { setAccountStatus({}); setAccount({ name: e.target.value }) }}
              maxLength={120}
            />
          </Field>
          <Field label="Email" hint="Email is read-only in v1.">
            <input className="input bg-gray-50 text-gray-400" value={user?.email || ''} readOnly />
          </Field>
          <Status {...accountStatus} />
          <button type="submit" disabled={accountSaving} className="btn-primary disabled:opacity-50">
            <Save className="w-4 h-4" />
            {accountSaving ? 'Saving...' : 'Save Account'}
          </button>
        </form>

        <form onSubmit={saveCompany} className="card p-6 space-y-4 lg:col-span-2">
          <div className="flex items-center gap-2">
            <Building2 className="w-4 h-4 text-brand-600" />
            <h2 className="text-sm font-bold text-gray-900">Company Profile</h2>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <Field label="Company Name">
              <input
                name="company_name"
                className="input"
                value={company.company_name}
                onChange={updateCompanyField}
                placeholder="Acme Ltd"
                maxLength={200}
                required
              />
            </Field>
            <Field label="Website">
              <input
                name="website"
                className="input"
                value={company.website}
                onChange={updateCompanyField}
                placeholder="https://example.com"
                maxLength={300}
              />
            </Field>
            <Field label="Industry">
              <input
                name="industry"
                className="input"
                value={company.industry}
                onChange={updateCompanyField}
                placeholder="Technology"
                maxLength={120}
              />
            </Field>
            <Field label="Company Size">
              <select
                name="company_size"
                className="input"
                value={company.company_size}
                onChange={updateCompanyField}
              >
                {COMPANY_SIZES.map(size => (
                  <option key={size} value={size}>{size || 'Select size'}</option>
                ))}
              </select>
            </Field>
            <Field label="Contact Name">
              <input
                name="contact_name"
                className="input"
                value={company.contact_name}
                onChange={updateCompanyField}
                placeholder="Security contact"
                maxLength={120}
              />
            </Field>
            <Field label="Contact Email">
              <input
                name="contact_email"
                type="email"
                className="input"
                value={company.contact_email}
                onChange={updateCompanyField}
                placeholder="security@example.com"
              />
            </Field>
          </div>
          <Status {...companyStatus} />
          <button type="submit" disabled={companySaving} className="btn-primary disabled:opacity-50">
            <Save className="w-4 h-4" />
            {companySaving ? 'Saving...' : 'Save Company'}
          </button>
        </form>

        <div className="card p-6 space-y-4">
          <div className="flex items-center gap-2">
            <CreditCard className="w-4 h-4 text-brand-600" />
            <h2 className="text-sm font-bold text-gray-900">Subscription</h2>
          </div>
          <div className="space-y-3 text-sm">
            <div className="flex items-center justify-between">
              <span className="text-gray-400">Plan</span>
              <PlanBadge plan={usage?.plan || subscription?.plan} />
            </div>
            <div className="flex items-center justify-between">
              <span className="text-gray-400">Status</span>
              <span className="font-medium text-gray-700 capitalize">{subscription?.status || 'active'}</span>
            </div>
            <div className="flex items-center justify-between">
              <span className="text-gray-400">Billing Provider</span>
              <span className="font-medium text-gray-700 capitalize">{subscription?.billing_provider || 'manual'}</span>
            </div>
            <p className="text-xs text-gray-400 pt-2 border-t border-gray-100">
              Payment integration is not enabled in v1. Subscription changes are managed manually.
            </p>
          </div>
          {usage && (
            <div className="pt-4 border-t border-gray-100 space-y-3">
              {/* Workspaces: account-level count vs account-level limit — correctly comparable */}
              <UsageLine
                label="Workspaces"
                used={usage.usage?.workspaces || 0}
                limit={usage.limits?.workspaces || 0}
              />
              {/* Domains and users are enforced per workspace, not account-wide.
                  Showing a cross-workspace total against a per-workspace limit is
                  misleading — display as plan allowances instead. */}
              <div className="space-y-1 text-xs text-gray-500">
                <div className="flex items-center justify-between">
                  <span>Domains per workspace</span>
                  <span className="font-semibold text-gray-700">
                    {(usage.limits?.domains ?? 0) >= 999999 ? '∞' : `up to ${usage.limits?.domains ?? 0}`}
                  </span>
                </div>
                <div className="flex items-center justify-between">
                  <span>Members per workspace</span>
                  <span className="font-semibold text-gray-700">
                    {(usage.limits?.users ?? 0) >= 999999 ? '∞' : `up to ${usage.limits?.users ?? 0}`}
                  </span>
                </div>
                <div className="flex items-center justify-between">
                  <span>History</span>
                  <span className="font-semibold text-gray-700">
                    {(usage.limits?.history_days ?? 0) >= 999999 ? 'Unlimited' : `${usage.limits?.history_days || 30} days`}
                  </span>
                </div>
              </div>
              <button type="button" disabled className="btn-primary w-full opacity-60 cursor-not-allowed">
                Upgrade coming soon
              </button>
            </div>
          )}
        </div>

        <div className="card p-6 space-y-4 lg:col-span-2">
          <div className="flex items-center gap-2">
            <Settings className="w-4 h-4 text-brand-600" />
            <h2 className="text-sm font-bold text-gray-900">API</h2>
          </div>
          <Field label="Base URL">
            <input
              className={`input mono text-xs ${!import.meta.env.VITE_API_BASE_URL ? 'text-red-500' : ''}`}
              value={import.meta.env.VITE_API_BASE_URL || ''}
              placeholder="VITE_API_BASE_URL is not set"
              readOnly
            />
            {!import.meta.env.VITE_API_BASE_URL && (
              <p className="text-xs text-red-500 mt-1">
                VITE_API_BASE_URL is not configured. Set it in your .env file.
              </p>
            )}
          </Field>
        </div>

        <NotificationPreferencesCard />
      </div>
    </div>
  )
}
