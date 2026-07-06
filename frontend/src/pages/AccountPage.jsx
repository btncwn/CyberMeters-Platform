import { parseServerDate } from '../utils/dates'
/**
 * AccountPage — Customer Portal Foundation v1
 *
 * Sections:
 *  1. Profile        — display name, email (read-only)
 *  2. Company Info   — editable: company name, website, industry, company size, country
 *  3. Subscription   — current plan + status per workspace (read-only in v1)
 *
 * Authentication: requireAuth enforced by ProtectedRoute in App.jsx.
 * Only the profile owner can write (backend enforces user_id from session).
 */

import { useState, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import {
  User, Building2, CreditCard, Save, AlertTriangle,
  CheckCircle, Globe, Briefcase, ChevronDown, Shield,
  KeyRound, Trash2, Plus, Gauge, Smartphone, Copy, LifeBuoy,
  ChevronRight,
} from 'lucide-react'
import { api } from '../api'
import { useAuth } from '../context/AuthContext'
import { USER_KEY } from '../context/authKeys'

// ── Plan display helpers ─────────────────────────────────────────────────────

const PLAN_CFG = {
  free:         { label: 'Free',         bg: 'bg-gray-100',    text: 'text-gray-600',    border: 'border-gray-200'   },
  starter:      { label: 'Starter',      bg: 'bg-blue-50',     text: 'text-blue-700',    border: 'border-blue-200'   },
  professional: { label: 'Professional', bg: 'bg-brand-50',    text: 'text-brand-700',   border: 'border-brand-200'  },
  enterprise:   { label: 'Enterprise',   bg: 'bg-amber-50',    text: 'text-amber-700',   border: 'border-amber-200'  },
}

const STATUS_CFG = {
  active:    { label: 'Active',    dot: 'bg-green-500',  text: 'text-green-700'  },
  trial:     { label: 'Trial',     dot: 'bg-blue-400',   text: 'text-blue-700'   },
  expired:   { label: 'Expired',   dot: 'bg-red-400',    text: 'text-red-700'    },
  cancelled: { label: 'Cancelled', dot: 'bg-gray-400',   text: 'text-gray-600'   },
}

function PlanBadge({ plan }) {
  const cfg = PLAN_CFG[plan] ?? PLAN_CFG.free
  return (
    <span className={`inline-flex items-center px-2.5 py-1 rounded-full border text-xs font-semibold ${cfg.bg} ${cfg.text} ${cfg.border}`}>
      {cfg.label}
    </span>
  )
}

function StatusDot({ status }) {
  const cfg = STATUS_CFG[status] ?? STATUS_CFG.active
  return (
    <span className={`inline-flex items-center gap-1.5 text-xs font-medium ${cfg.text}`}>
      <span className={`w-2 h-2 rounded-full ${cfg.dot}`} />
      {cfg.label}
    </span>
  )
}

// ── Section wrapper ───────────────────────────────────────────────────────────

function Section({ icon: Icon, title, children }) {
  return (
    <div className="card mb-6">
      <div className="flex items-center gap-2.5 mb-5 pb-4 border-b border-gray-100">
        <div className="w-8 h-8 rounded-lg bg-brand-50 flex items-center justify-center flex-shrink-0">
          <Icon className="w-4 h-4 text-brand-600" />
        </div>
        <h2 className="font-semibold text-gray-900">{title}</h2>
      </div>
      {children}
    </div>
  )
}

// ── Form field ────────────────────────────────────────────────────────────────

function Field({ label, children, hint }) {
  return (
    <div className="mb-4">
      <label className="block text-xs font-semibold text-gray-600 uppercase tracking-wider mb-1.5">
        {label}
      </label>
      {children}
      {hint && <p className="text-xs text-gray-400 mt-1">{hint}</p>}
    </div>
  )
}

// ── Main component ────────────────────────────────────────────────────────────

const INDUSTRIES = [
  '', 'Technology', 'Financial Services', 'Healthcare', 'Retail & E-commerce',
  'Manufacturing', 'Government & Public Sector', 'Education', 'Legal',
  'Media & Entertainment', 'Telecommunications', 'Energy & Utilities',
  'Real Estate', 'Professional Services', 'Non-profit', 'Other',
]

const COMPANY_SIZES = [
  { value: '', label: 'Select…' },
  { value: '1-10',     label: '1–10 employees'     },
  { value: '11-50',    label: '11–50 employees'    },
  { value: '51-200',   label: '51–200 employees'   },
  { value: '201-1000', label: '201–1,000 employees' },
  { value: '1000+',    label: '1,000+ employees'   },
]

// ── Plan Limits Card ─────────────────────────────────────────────────────────

function UsageBar({ label, used, limit, note }) {
  const pct   = limit > 0 ? Math.min(100, Math.round((used / limit) * 100)) : 0
  const near  = pct >= 80
  const full  = pct >= 100
  const color = full ? 'bg-red-500' : near ? 'bg-amber-400' : 'bg-brand-500'
  return (
    <div className="mb-3 last:mb-0">
      <div className="flex items-center justify-between mb-1">
        <span className="text-xs text-gray-600">{label}</span>
        <span className={`text-xs font-semibold ${full ? 'text-red-600' : near ? 'text-amber-600' : 'text-gray-500'}`}>
          {used} / {limit >= 999 ? '∞' : limit}
          {note && <span className="ml-1 font-normal text-gray-400">{note}</span>}
        </span>
      </div>
      <div className="h-1.5 bg-gray-100 rounded-full overflow-hidden">
        <div className={`h-full rounded-full transition-all ${color}`} style={{ width: `${pct}%` }} />
      </div>
    </div>
  )
}

function PlanLimitsCard({ planLimits }) {
  if (!planLimits) return null
  const { plan, limits, usage } = planLimits
  const unlimited = (n) => n >= 999999

  return (
    <div className="card mb-6">
      <div className="flex items-center gap-2.5 mb-5 pb-4 border-b border-gray-100">
        <div className="w-8 h-8 rounded-lg bg-brand-50 flex items-center justify-center flex-shrink-0">
          <Gauge className="w-4 h-4 text-brand-600" />
        </div>
        <div className="flex items-center gap-2 flex-1">
          <h2 className="font-semibold text-gray-900">Plan Usage</h2>
          <PlanBadge plan={plan} />
        </div>
      </div>

      {/* Workspaces — account-level limit, correctly comparable to usage */}
      <UsageBar
        label="Workspaces"
        used={usage.workspaces}
        limit={limits.workspaces}
      />

      {/* Domains & users are enforced per workspace, not account-wide.
          Show plan allowances as features rather than misleading progress bars. */}
      <div className="mt-3 space-y-1.5 text-xs text-gray-500 border-t border-gray-50 pt-3">
        <div className="flex items-center justify-between">
          <span>Domains per workspace</span>
          <span className="font-semibold text-gray-700">
            {unlimited(limits.domains) ? '∞' : `up to ${limits.domains}`}
          </span>
        </div>
        <div className="flex items-center justify-between">
          <span>Members per workspace</span>
          <span className="font-semibold text-gray-700">
            {unlimited(limits.users) ? '∞' : `up to ${limits.users}`}
          </span>
        </div>
        <div className="flex items-center justify-between">
          <span>History</span>
          <span className="font-semibold text-gray-700">
            {unlimited(limits.history_days) ? 'Unlimited' : `${limits.history_days} days`}
          </span>
        </div>
      </div>

      {plan === 'free' || plan === 'starter' ? (
        <div className="mt-4 pt-4 border-t border-gray-50">
          <p className="text-xs text-brand-600 font-medium">Upgrade for higher limits →</p>
          <p className="text-[10px] text-gray-400 mt-0.5">Billing available in an upcoming release.</p>
        </div>
      ) : null}
    </div>
  )
}

export default function AccountPage() {
  const navigate = useNavigate()
  const { user: authUser, login } = useAuth()

  // Remote state
  const [profile,      setProfile]      = useState(null)
  const [subscription, setSubscription] = useState(null)   // singular — backend returns { subscription: {...} }
  const [planLimits,   setPlanLimits]   = useState(null)
  const [apiTokens,    setApiTokens]    = useState([])
  const [loading,      setLoading]      = useState(true)
  const [loadError,    setLoadError]    = useState(null)

  // Edit form state (synced from profile on load)
  const [form, setForm] = useState({
    name:         '',
    company_name: '',
    website:      '',
    industry:     '',
    company_size: '',
    country:      '',
  })

  const [saving,     setSaving]     = useState(false)
  const [saveError,  setSaveError]  = useState(null)
  const [saveOk,     setSaveOk]     = useState(false)
  const [tokenName,   setTokenName]   = useState('')
  const [tokenScope,  setTokenScope]  = useState('read')
  const [tokenExpiry, setTokenExpiry] = useState('never')
  const [newToken,    setNewToken]    = useState(null)
  const [tokenBusy,   setTokenBusy]   = useState(false)
  const [tokenError,  setTokenError]  = useState(null)

  // MFA state
  const [mfaStatus,        setMfaStatus]        = useState(null)   // { mfa_enabled, mfa_enabled_at }
  const [mfaStep,          setMfaStep]          = useState('idle') // idle | setup | verify | codes | disable
  const [mfaOtpUri,        setMfaOtpUri]        = useState(null)
  const [mfaSecretBase32,  setMfaSecretBase32]  = useState(null)
  const [mfaCode,          setMfaCode]          = useState('')
  const [mfaDisableInput,  setMfaDisableInput]  = useState('')
  const [mfaRecoveryCodes, setMfaRecoveryCodes] = useState(null)
  const [mfaBusy,          setMfaBusy]          = useState(false)
  const [mfaError,         setMfaError]         = useState(null)
  const [mfaSuccess,       setMfaSuccess]       = useState(null)
  const [copiedSecret,     setCopiedSecret]     = useState(false)

  useEffect(() => {
    async function load() {
      setLoading(true)
      setLoadError(null)
      try {
        const [profileRes, subRes, tokenRes, limitsRes, mfaRes] = await Promise.allSettled([
          api.getAccountProfile(),
          api.getSubscription(),
          api.getApiTokens(),
          api.getAccountUsage(),
          api.getMfaStatus(),
        ])

        if (profileRes.status === 'fulfilled') {
          const { user: u, profile: p } = profileRes.value
          setProfile(p)
          setForm({
            name:         u?.name         || '',
            company_name: p?.company_name || '',
            website:      p?.website      || '',
            industry:     p?.industry     || '',
            company_size: p?.company_size || '',
            country:      p?.country      || '',
          })
        } else {
          setLoadError(profileRes.reason?.message || 'Failed to load profile')
        }

        if (subRes.status === 'fulfilled') {
          // Backend returns { subscription: {...} } — singular object, not an array.
          setSubscription(subRes.value.subscription || null)
        }
        if (tokenRes.status === 'fulfilled') {
          setApiTokens(tokenRes.value.tokens || [])
        }
        if (limitsRes.status === 'fulfilled') {
          setPlanLimits(limitsRes.value)
        }
        if (mfaRes.status === 'fulfilled') {
          setMfaStatus(mfaRes.value)
        }
      } finally {
        setLoading(false)
      }
    }
    load()
  }, [])

  function handleChange(e) {
    setSaveOk(false)
    setSaveError(null)
    setForm(prev => ({ ...prev, [e.target.name]: e.target.value }))
  }

  async function handleSave(e) {
    e.preventDefault()
    setSaving(true)
    setSaveError(null)
    setSaveOk(false)
    try {
      const res = await api.updateAccountProfile(form)
      setProfile(res.profile)
      setSaveOk(true)
      // Sync updated name into auth context so UserMenu reflects immediately
      if (res.user && form.name !== authUser?.name) {
        const stored = localStorage.getItem(USER_KEY)
        if (stored) {
          try {
            const parsed = JSON.parse(stored)
            localStorage.setItem(USER_KEY, JSON.stringify({ ...parsed, name: res.user.name }))
          } catch { /* ignore */ }
        }
      }
    } catch (e) {
      setSaveError(e.message)
    } finally {
      setSaving(false)
    }
  }

  async function handleCreateToken(e) {
    e.preventDefault()
    const name = tokenName.trim()
    if (!name || tokenBusy) return
    setTokenBusy(true)
    setTokenError(null)
    setNewToken(null)
    try {
      // Compute expires_at from the selected expiry option
      let expires_at = null
      if (tokenExpiry !== 'never') {
        const days = parseInt(tokenExpiry, 10)
        if (!isNaN(days)) {
          const d = new Date()
          d.setDate(d.getDate() + days)
          expires_at = d.toISOString()
        }
      }
      const res = await api.createApiToken({ name, scope: tokenScope, expires_at })
      setNewToken(res.token)
      setTokenName('')
      setTokenScope('read')
      setTokenExpiry('never')
      const list = await api.getApiTokens()
      setApiTokens(list.tokens || [])
    } catch (e) {
      setTokenError(e.message)
    } finally {
      setTokenBusy(false)
    }
  }

  async function handleRevokeToken(id) {
    if (!id || tokenBusy) return
    setTokenBusy(true)
    setTokenError(null)
    try {
      await api.revokeApiToken(id)
      setApiTokens(prev => prev.map(t => t.id === id ? { ...t, status: 'revoked' } : t))
    } catch (e) {
      setTokenError(e.message)
    } finally {
      setTokenBusy(false)
    }
  }


  // ── MFA handlers ─────────────────────────────────────────────────────────────

  async function handleMfaSetup() {
    setMfaBusy(true); setMfaError(null); setMfaSuccess(null)
    try {
      const res = await api.setupMfa()
      setMfaOtpUri(res.otpauth_uri)
      setMfaSecretBase32(res.secret_base32)
      setMfaCode('')
      setMfaStep('setup')
    } catch (e) { setMfaError(e.message) }
    finally { setMfaBusy(false) }
  }

  async function handleMfaVerify() {
    if (!mfaCode || mfaCode.length !== 6) return
    setMfaBusy(true); setMfaError(null)
    try {
      const res = await api.verifyMfaSetup(mfaCode)
      setMfaRecoveryCodes(res.recovery_codes)
      setMfaStatus({ mfa_enabled: true, mfa_enabled_at: new Date().toISOString() })
      setMfaStep('codes')
      setMfaCode('')
    } catch (e) { setMfaError(e.message); setMfaCode('') }
    finally { setMfaBusy(false) }
  }

  async function handleMfaDisable() {
    if (!mfaDisableInput) return
    setMfaBusy(true); setMfaError(null)
    const isCode = /^\d{6}$/.test(mfaDisableInput.trim())
    try {
      await api.disableMfa(isCode ? { code: mfaDisableInput } : { password: mfaDisableInput })
      setMfaStatus({ mfa_enabled: false, mfa_enabled_at: null })
      setMfaStep('idle')
      setMfaDisableInput('')
      setMfaSuccess('MFA has been disabled.')
    } catch (e) { setMfaError(e.message) }
    finally { setMfaBusy(false) }
  }

  function mfaReset() {
    setMfaStep('idle'); setMfaOtpUri(null); setMfaSecretBase32(null)
    setMfaCode(''); setMfaDisableInput(''); setMfaRecoveryCodes(null)
    setMfaError(null); setMfaSuccess(null)
  }

  function copySecret() {
    if (mfaSecretBase32) {
      navigator.clipboard.writeText(mfaSecretBase32).then(() => {
        setCopiedSecret(true); setTimeout(() => setCopiedSecret(false), 2000)
      }).catch(() => {})
    }
  }

  return (
    <div className="max-w-screen-xl mx-auto px-6 py-8">
      {/* Page header */}
      <div className="mb-8">
        <h1 className="text-2xl font-bold text-gray-900">Account</h1>
        <p className="text-sm text-gray-500 mt-1">Manage your profile, company details, and subscription.</p>
      </div>

      {loading ? (
        <div className="card p-16 text-center">
          <p className="text-sm text-gray-400">Loading…</p>
        </div>
      ) : loadError ? (
        <div className="card p-8 text-center">
          <AlertTriangle className="w-8 h-8 text-red-400 mx-auto mb-3" />
          <p className="text-sm text-red-600">{loadError}</p>
        </div>
      ) : (
        <form onSubmit={handleSave}>
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">

            {/* Left column — Profile + Company */}
            <div className="lg:col-span-2">

              {/* ── Profile ──────────────────────────────────────────────── */}
              <Section icon={User} title="Profile">
                <Field label="Email address" hint="Email cannot be changed.">
                  <input
                    type="email"
                    value={authUser?.email || ''}
                    readOnly
                    className="input bg-gray-50 text-gray-400 cursor-not-allowed"
                  />
                </Field>
                <Field label="Display name">
                  <input
                    type="text"
                    name="name"
                    value={form.name}
                    onChange={handleChange}
                    placeholder="Your full name"
                    className="input"
                    maxLength={120}
                  />
                </Field>
              </Section>

              {/* ── Company Information ───────────────────────────────────── */}
              <Section icon={Building2} title="Company Information">
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-x-5">
                  <Field label="Company name">
                    <input
                      type="text"
                      name="company_name"
                      value={form.company_name}
                      onChange={handleChange}
                      placeholder="Acme Corp"
                      className="input"
                      maxLength={200}
                    />
                  </Field>
                  <Field label="Website" hint="Include https://">
                    <input
                      type="url"
                      name="website"
                      value={form.website}
                      onChange={handleChange}
                      placeholder="https://example.com"
                      className="input"
                      maxLength={300}
                    />
                  </Field>
                  <Field label="Industry">
                    <div className="relative">
                      <select
                        name="industry"
                        value={form.industry}
                        onChange={handleChange}
                        className="input appearance-none pr-8"
                      >
                        {INDUSTRIES.map(i => (
                          <option key={i} value={i}>{i || 'Select…'}</option>
                        ))}
                      </select>
                      <ChevronDown className="absolute right-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-gray-400 pointer-events-none" />
                    </div>
                  </Field>
                  <Field label="Company size">
                    <div className="relative">
                      <select
                        name="company_size"
                        value={form.company_size}
                        onChange={handleChange}
                        className="input appearance-none pr-8"
                      >
                        {COMPANY_SIZES.map(s => (
                          <option key={s.value} value={s.value}>{s.label}</option>
                        ))}
                      </select>
                      <ChevronDown className="absolute right-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-gray-400 pointer-events-none" />
                    </div>
                  </Field>
                  <Field label="Country" hint="Country of primary operations">
                    <div className="relative flex items-center">
                      <Globe className="absolute left-3 w-4 h-4 text-gray-400 pointer-events-none" />
                      <input
                        type="text"
                        name="country"
                        value={form.country}
                        onChange={handleChange}
                        placeholder="United Kingdom"
                        className="input pl-9"
                        maxLength={100}
                      />
                    </div>
                  </Field>
                </div>

                {/* Save feedback */}
                {saveError && (
                  <div className="flex items-center gap-2 p-3 rounded-xl bg-red-50 border border-red-100 mb-4">
                    <AlertTriangle className="w-4 h-4 text-red-500 flex-shrink-0" />
                    <p className="text-xs text-red-600">{saveError}</p>
                  </div>
                )}
                {saveOk && (
                  <div className="flex items-center gap-2 p-3 rounded-xl bg-green-50 border border-green-100 mb-4">
                    <CheckCircle className="w-4 h-4 text-green-500 flex-shrink-0" />
                    <p className="text-xs text-green-700">Profile saved successfully.</p>
                  </div>
                )}

                <div className="flex justify-end">
                  <button
                    type="submit"
                    disabled={saving}
                    className="btn-primary flex items-center gap-2 disabled:opacity-50"
                  >
                    <Save className="w-4 h-4" />
                    {saving ? 'Saving…' : 'Save changes'}
                  </button>
                </div>
              </Section>
            </div>

            {/* Right column — Plan Usage + Subscription */}
            <div className="lg:col-span-1">
              <PlanLimitsCard planLimits={planLimits} />
              <Section icon={CreditCard} title="Subscription">

                {!subscription ? (
                  <div className="text-center py-6">
                    <Briefcase className="w-8 h-8 text-gray-200 mx-auto mb-2" />
                    <p className="text-sm text-gray-400">No subscription found.</p>
                    <p className="text-xs text-gray-300 mt-1">Your account is on the free plan.</p>
                  </div>
                ) : (
                  <div className="p-3.5 rounded-xl border border-gray-100 bg-gray-50/50 space-y-2">
                    <div className="flex items-center justify-between">
                      <span className="text-xs text-gray-500">Plan</span>
                      <PlanBadge plan={subscription.plan} />
                    </div>
                    <div className="flex items-center justify-between">
                      <span className="text-xs text-gray-500">Status</span>
                      <StatusDot status={subscription.status} />
                    </div>
                    {subscription.billing_provider && (
                      <div className="flex items-center justify-between">
                        <span className="text-xs text-gray-500">Billing</span>
                        <span className="text-xs font-medium text-gray-700 capitalize">{subscription.billing_provider}</span>
                      </div>
                    )}
                    {subscription.current_period_end ? (
                      <div className="flex items-center justify-between">
                        <span className="text-xs text-gray-500">Renews</span>
                        <span className="text-xs text-gray-400">
                          {parseServerDate(subscription.current_period_end).toLocaleDateString(undefined, { month: 'short', day: 'numeric', year: 'numeric' })}
                        </span>
                      </div>
                    ) : subscription.trial_ends_at ? (
                      <div className="flex items-center justify-between">
                        <span className="text-xs text-gray-500">Trial ends</span>
                        <span className="text-xs text-gray-400">
                          {parseServerDate(subscription.trial_ends_at).toLocaleDateString(undefined, { month: 'short', day: 'numeric', year: 'numeric' })}
                        </span>
                      </div>
                    ) : null}
                  </div>
                )}

                <div className="mt-5 p-4 rounded-xl bg-brand-50 border border-brand-100">
                  <div className="flex items-center gap-2 mb-2">
                    <Shield className="w-4 h-4 text-brand-600" />
                    <p className="text-xs font-semibold text-brand-700">Upgrade your plan</p>
                  </div>
                  <p className="text-xs text-brand-600 leading-relaxed">
                    Unlock unlimited domains, advanced reporting, and MSP portfolio features.
                  </p>
                  <p className="text-[10px] text-brand-400 mt-2">Billing available in an upcoming release.</p>
                </div>
              </Section>

              {/* ── Two-Factor Authentication ─────────────────────────── */}
              <Section icon={Smartphone} title="Two-Factor Authentication">
                {mfaSuccess && (
                  <div className="flex items-center gap-2 p-3 rounded-xl bg-green-50 border border-green-100 mb-4">
                    <CheckCircle className="w-4 h-4 text-green-500 flex-shrink-0" />
                    <p className="text-xs text-green-700">{mfaSuccess}</p>
                  </div>
                )}
                {mfaError && (
                  <div className="flex items-center gap-2 p-3 rounded-xl bg-red-50 border border-red-100 mb-4">
                    <AlertTriangle className="w-4 h-4 text-red-500 flex-shrink-0" />
                    <p className="text-xs text-red-600">{mfaError}</p>
                  </div>
                )}

                {/* Status indicator */}
                {mfaStep === 'idle' && (
                  <div className="space-y-4">
                    <div className="flex items-center justify-between p-3 rounded-xl border border-gray-100 bg-gray-50/50">
                      <div>
                        <p className="text-sm font-semibold text-gray-800">Authenticator app (TOTP)</p>
                        <p className="text-xs text-gray-400 mt-0.5">
                          {mfaStatus?.mfa_enabled
                            ? `Enabled ${mfaStatus.mfa_enabled_at ? 'on ' + parseServerDate(mfaStatus.mfa_enabled_at).toLocaleDateString() : ''}`
                            : 'Not enabled'}
                        </p>
                      </div>
                      <span className={`text-xs font-semibold px-2 py-1 rounded-full ${mfaStatus?.mfa_enabled ? 'bg-green-50 text-green-700' : 'bg-gray-100 text-gray-500'}`}>
                        {mfaStatus?.mfa_enabled ? 'Active' : 'Off'}
                      </span>
                    </div>

                    {!mfaStatus?.mfa_enabled ? (
                      <button
                        type="button"
                        onClick={handleMfaSetup}
                        disabled={mfaBusy}
                        className="btn-primary w-full justify-center disabled:opacity-50"
                      >
                        <Smartphone className="w-4 h-4" />
                        {mfaBusy ? 'Setting up…' : 'Enable MFA'}
                      </button>
                    ) : (
                      <button
                        type="button"
                        onClick={() => { setMfaStep('disable'); setMfaError(null) }}
                        disabled={mfaBusy}
                        className="w-full flex items-center justify-center gap-2 px-4 py-2.5 rounded-xl border border-red-200 text-red-600 text-sm font-medium hover:bg-red-50 disabled:opacity-50 transition-colors"
                      >
                        Disable MFA
                      </button>
                    )}
                  </div>
                )}

                {/* Setup step: show secret + manual entry instructions */}
                {mfaStep === 'setup' && (
                  <div className="space-y-4">
                    <div className="p-3 rounded-xl bg-brand-50 border border-brand-100">
                      <p className="text-xs font-semibold text-brand-800 mb-1">1. Open your authenticator app</p>
                      <p className="text-xs text-brand-700">Add a new account manually and enter the key below. Compatible with Google Authenticator, Authy, 1Password, Bitwarden, and any RFC 6238 TOTP app.</p>
                    </div>

                    <div>
                      <label className="block text-xs font-semibold text-gray-600 uppercase tracking-wider mb-1.5">Account key (base32)</label>
                      <div className="relative">
                        <code className="block w-full px-3 py-2.5 pr-10 bg-gray-50 border border-gray-200 rounded-xl text-sm font-mono text-gray-800 break-all select-all">
                          {mfaSecretBase32}
                        </code>
                        <button
                          type="button"
                          onClick={copySecret}
                          className="absolute right-2 top-1/2 -translate-y-1/2 p-1.5 rounded-lg text-gray-400 hover:text-gray-700 hover:bg-gray-100"
                          title="Copy secret"
                        >
                          {copiedSecret ? <CheckCircle className="w-4 h-4 text-green-500" /> : <Copy className="w-4 h-4" />}
                        </button>
                      </div>
                      <p className="text-[10px] text-gray-400 mt-1">Issuer: CyberMeters · Algorithm: SHA-1 · Digits: 6 · Period: 30s</p>
                    </div>

                    <div>
                      <label className="block text-xs font-semibold text-gray-600 uppercase tracking-wider mb-1.5">2. Enter the 6-digit code to confirm</label>
                      <input
                        type="text"
                        inputMode="numeric"
                        pattern="\d{6}"
                        maxLength={6}
                        className="input text-center text-lg font-mono tracking-[0.4em] py-3"
                        placeholder="000000"
                        value={mfaCode}
                        onChange={e => setMfaCode(e.target.value.replace(/\D/g, ''))}
                        autoComplete="one-time-code"
                      />
                    </div>

                    <div className="flex gap-2">
                      <button type="button" onClick={mfaReset} className="flex-1 btn-secondary justify-center">Cancel</button>
                      <button
                        type="button"
                        onClick={handleMfaVerify}
                        disabled={mfaBusy || mfaCode.length !== 6}
                        className="flex-1 btn-primary justify-center disabled:opacity-50"
                      >
                        {mfaBusy ? 'Verifying…' : 'Verify & enable'}
                      </button>
                    </div>
                  </div>
                )}

                {/* Recovery codes — shown once after successful enable */}
                {mfaStep === 'codes' && mfaRecoveryCodes && (
                  <div className="space-y-4">
                    <div className="p-3 rounded-xl bg-amber-50 border border-amber-100">
                      <p className="text-xs font-semibold text-amber-800 mb-1">Save your recovery codes</p>
                      <p className="text-xs text-amber-700">Each code can be used once if you lose access to your authenticator. Store them securely — they will not be shown again.</p>
                    </div>
                    <div className="grid grid-cols-2 gap-1.5">
                      {mfaRecoveryCodes.map((code, i) => (
                        <code key={i} className="block px-3 py-1.5 bg-gray-50 border border-gray-200 rounded-lg text-xs font-mono text-gray-800 text-center select-all">
                          {code}
                        </code>
                      ))}
                    </div>
                    <div className="flex items-center gap-2 p-3 rounded-xl bg-green-50 border border-green-100">
                      <CheckCircle className="w-4 h-4 text-green-500 flex-shrink-0" />
                      <p className="text-xs text-green-700 font-medium">MFA is now active on your account.</p>
                    </div>
                    <button type="button" onClick={mfaReset} className="w-full btn-primary justify-center">
                      Done
                    </button>
                  </div>
                )}

                {/* Disable confirmation */}
                {mfaStep === 'disable' && (
                  <div className="space-y-4">
                    <div className="p-3 rounded-xl bg-red-50 border border-red-100">
                      <p className="text-xs font-semibold text-red-800 mb-1">Disable two-factor authentication</p>
                      <p className="text-xs text-red-700">Enter your current 6-digit TOTP code or account password to confirm.</p>
                    </div>
                    <div>
                      <label className="block text-xs font-semibold text-gray-600 uppercase tracking-wider mb-1.5">TOTP code or password</label>
                      <input
                        type="text"
                        className="input font-mono"
                        placeholder="6-digit code or password"
                        value={mfaDisableInput}
                        onChange={e => setMfaDisableInput(e.target.value)}
                        autoComplete="off"
                        autoFocus
                      />
                    </div>
                    <div className="flex gap-2">
                      <button type="button" onClick={mfaReset} className="flex-1 btn-secondary justify-center">Cancel</button>
                      <button
                        type="button"
                        onClick={handleMfaDisable}
                        disabled={mfaBusy || !mfaDisableInput}
                        className="flex-1 flex items-center justify-center gap-2 px-4 py-2.5 rounded-xl bg-red-600 hover:bg-red-700 text-white text-sm font-medium disabled:opacity-50 transition-colors"
                      >
                        {mfaBusy ? 'Disabling…' : 'Disable MFA'}
                      </button>
                    </div>
                  </div>
                )}
              </Section>

              <Section icon={KeyRound} title="API Tokens">
                <div className="space-y-4">
                  <div className="space-y-3">
                    <div>
                      <label className="block text-xs font-semibold text-gray-600 uppercase tracking-wider mb-1.5">
                        Token name
                      </label>
                      <input
                        type="text"
                        value={tokenName}
                        onChange={(e) => { setTokenName(e.target.value); setTokenError(null) }}
                        placeholder="GitHub Actions"
                        className="input"
                        maxLength={120}
                      />
                    </div>
                    <div className="grid grid-cols-2 gap-3">
                      <div>
                        <label className="block text-xs font-semibold text-gray-600 uppercase tracking-wider mb-1.5">
                          Scope
                        </label>
                        <select
                          value={tokenScope}
                          onChange={(e) => setTokenScope(e.target.value)}
                          className="input"
                        >
                          <option value="read">read — view data only</option>
                          <option value="write">write — trigger scans &amp; edits</option>
                          <option value="admin">admin — full workspace access</option>
                        </select>
                      </div>
                      <div>
                        <label className="block text-xs font-semibold text-gray-600 uppercase tracking-wider mb-1.5">
                          Expires
                        </label>
                        <select
                          value={tokenExpiry}
                          onChange={(e) => setTokenExpiry(e.target.value)}
                          className="input"
                        >
                          <option value="never">Never</option>
                          <option value="7">7 days</option>
                          <option value="30">30 days</option>
                          <option value="90">90 days</option>
                          <option value="365">1 year</option>
                        </select>
                      </div>
                    </div>
                    <button
                      type="button"
                      onClick={handleCreateToken}
                      disabled={tokenBusy || !tokenName.trim()}
                      className="btn-primary w-full justify-center disabled:opacity-50"
                    >
                      <Plus className="w-4 h-4" />
                      Generate token
                    </button>
                  </div>

                  {newToken && (
                    <div className="p-3 rounded-xl bg-amber-50 border border-amber-100">
                      <p className="text-xs font-semibold text-amber-800 mb-1">Store this token now. It will never be shown again.</p>
                      <code className="block text-xs text-amber-900 break-all bg-white/60 rounded-lg p-2">{newToken}</code>
                    </div>
                  )}

                  {tokenError && (
                    <div className="flex items-center gap-2 p-3 rounded-xl bg-red-50 border border-red-100">
                      <AlertTriangle className="w-4 h-4 text-red-500 flex-shrink-0" />
                      <p className="text-xs text-red-600">{tokenError}</p>
                    </div>
                  )}

                  {apiTokens.length === 0 ? (
                    <div className="text-center py-5 border border-dashed border-gray-200 rounded-xl">
                      <KeyRound className="w-7 h-7 text-gray-200 mx-auto mb-2" />
                      <p className="text-sm text-gray-400">No API tokens yet.</p>
                    </div>
                  ) : (
                    <ul className="space-y-2">
                      {apiTokens.map(token => (
                        <li key={token.id} className="p-3 rounded-xl border border-gray-100 bg-gray-50/50">
                          <div className="flex items-start justify-between gap-3">
                            <div className="min-w-0">
                              <p className="text-sm font-semibold text-gray-900 truncate">{token.name}</p>
                              <p className="text-[10px] text-gray-400 mt-0.5">
                                Created {token.created_at ? parseServerDate(token.created_at).toLocaleDateString() : 'unknown'}
                              </p>
                              <p className="text-[10px] text-gray-400">
                                Last used {token.last_used_at ? parseServerDate(token.last_used_at).toLocaleDateString() : 'never'}
                              </p>
                            </div>
                            <div className="flex items-center gap-2 flex-shrink-0">
                              <span className={`text-[10px] font-semibold uppercase ${token.status === 'active' ? 'text-green-600' : 'text-gray-400'}`}>
                                {token.status}
                              </span>
                              {token.status === 'active' && (
                                <button
                                  type="button"
                                  onClick={() => handleRevokeToken(token.id)}
                                  disabled={tokenBusy}
                                  className="p-1.5 rounded-lg text-gray-400 hover:text-red-600 hover:bg-red-50 disabled:opacity-50"
                                  title="Revoke token"
                                >
                                  <Trash2 className="w-4 h-4" />
                                </button>
                              )}
                            </div>
                          </div>
                        </li>
                      ))}
                    </ul>
                  )}
                </div>
              </Section>

              {/* ── Security & Privacy Quick Links ──────────────────────── */}
              <div className="card p-4 mt-6 divide-y divide-gray-50">
                <button
                  type="button"
                  onClick={() => navigate('/account/security')}
                  className="w-full flex items-center gap-3 text-left group pb-3"
                >
                  <div className="w-9 h-9 rounded-lg bg-brand-50 flex items-center justify-center flex-shrink-0 group-hover:bg-brand-100 transition-colors">
                    <Shield className="w-4 h-4 text-brand-600" />
                  </div>
                  <div className="flex-1 min-w-0">
                    <p className="text-sm font-semibold text-gray-900">Security</p>
                    <p className="text-xs text-gray-400">Login history &amp; active sessions</p>
                  </div>
                  <ChevronRight className="w-4 h-4 text-gray-300 group-hover:text-gray-500 transition-colors flex-shrink-0" />
                </button>
                <button
                  type="button"
                  onClick={() => navigate('/account/privacy')}
                  className="w-full flex items-center gap-3 text-left group pt-3"
                >
                  <div className="w-9 h-9 rounded-lg bg-blue-50 flex items-center justify-center flex-shrink-0 group-hover:bg-blue-100 transition-colors">
                    <LifeBuoy className="w-4 h-4 text-blue-600" />
                  </div>
                  <div className="flex-1 min-w-0">
                    <p className="text-sm font-semibold text-gray-900">Privacy &amp; Data</p>
                    <p className="text-xs text-gray-400">Export data, deletion requests, retention policy</p>
                  </div>
                  <ChevronRight className="w-4 h-4 text-gray-300 group-hover:text-gray-500 transition-colors flex-shrink-0" />
                </button>
              </div>
            </div>

          </div>
        </form>
      )}
    </div>
  )
}
