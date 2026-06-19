import { useEffect, useState } from 'react'
import {
  AlertTriangle, Building2, CheckCircle, CreditCard,
  Save, Settings, User,
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
        const [profileRes, companyRes, subscriptionRes] = await Promise.all([
          api.getAccountProfile(),
          api.getCompanyProfile(),
          api.getSubscription(),
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
              <PlanBadge plan={subscription?.plan} />
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
        </div>

        <div className="card p-6 space-y-4 lg:col-span-2">
          <div className="flex items-center gap-2">
            <Settings className="w-4 h-4 text-brand-600" />
            <h2 className="text-sm font-bold text-gray-900">API</h2>
          </div>
          <Field label="Base URL">
            <input
              className="input mono text-xs"
              value={import.meta.env.VITE_API_BASE_URL || 'https://cybermeters-platform.ttrnn47.workers.dev/api'}
              readOnly
            />
          </Field>
        </div>
      </div>
    </div>
  )
}
