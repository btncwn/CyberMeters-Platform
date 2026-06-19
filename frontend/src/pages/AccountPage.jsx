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
import {
  User, Building2, CreditCard, Save, AlertTriangle,
  CheckCircle, Globe, Briefcase, ChevronDown, Shield,
  KeyRound, Trash2, Plus,
} from 'lucide-react'
import { api } from '../api'
import { useAuth } from '../context/AuthContext'

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

export default function AccountPage() {
  const { user: authUser, login } = useAuth()

  // Remote state
  const [profile,       setProfile]       = useState(null)
  const [subscriptions, setSubscriptions] = useState([])
  const [apiTokens,     setApiTokens]     = useState([])
  const [loading,       setLoading]       = useState(true)
  const [loadError,     setLoadError]     = useState(null)

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
  const [tokenName,  setTokenName]  = useState('')
  const [newToken,   setNewToken]   = useState(null)
  const [tokenBusy,  setTokenBusy]  = useState(false)
  const [tokenError, setTokenError] = useState(null)

  useEffect(() => {
    async function load() {
      setLoading(true)
      setLoadError(null)
      try {
        const [profileRes, subRes, tokenRes] = await Promise.allSettled([
          api.getAccountProfile(),
          api.getSubscription(),
          api.getApiTokens(),
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
          setSubscriptions(subRes.value.subscriptions || [])
        }
        if (tokenRes.status === 'fulfilled') {
          setApiTokens(tokenRes.value.tokens || [])
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
        const stored = localStorage.getItem('cybermeters_auth_user')
        if (stored) {
          try {
            const parsed = JSON.parse(stored)
            localStorage.setItem('cybermeters_auth_user', JSON.stringify({ ...parsed, name: res.user.name }))
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
      const res = await api.createApiToken(name)
      setNewToken(res.token)
      setTokenName('')
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

            {/* Right column — Subscription */}
            <div className="lg:col-span-1">
              <Section icon={CreditCard} title="Subscription">

                {subscriptions.length === 0 ? (
                  <div className="text-center py-6">
                    <Briefcase className="w-8 h-8 text-gray-200 mx-auto mb-2" />
                    <p className="text-sm text-gray-400">No workspaces found.</p>
                    <p className="text-xs text-gray-300 mt-1">Create a workspace to see subscription details.</p>
                  </div>
                ) : (
                  <ul className="space-y-3">
                    {subscriptions.map(sub => (
                      <li key={sub.id} className="p-3.5 rounded-xl border border-gray-100 bg-gray-50/50">
                        <div className="flex items-start justify-between gap-2 mb-2">
                          <div className="min-w-0">
                            <p className="text-sm font-semibold text-gray-900 truncate">{sub.workspace_name}</p>
                            <p className="text-[10px] text-gray-400 uppercase tracking-wider font-medium mt-0.5">{sub.role}</p>
                          </div>
                          <PlanBadge plan={sub.plan} />
                        </div>
                        <div className="flex items-center justify-between">
                          <StatusDot status={sub.status} />
                          {sub.expires_at ? (
                            <span className="text-[10px] text-gray-400">
                              Expires {new Date(sub.expires_at).toLocaleDateString(undefined, { month: 'short', day: 'numeric', year: 'numeric' })}
                            </span>
                          ) : (
                            <span className="text-[10px] text-gray-400">No expiry</span>
                          )}
                        </div>
                      </li>
                    ))}
                  </ul>
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

              <Section icon={KeyRound} title="API Tokens">
                <div className="space-y-4">
                  <div>
                    <label className="block text-xs font-semibold text-gray-600 uppercase tracking-wider mb-1.5">
                      Token name
                    </label>
                    <div className="flex gap-2">
                      <input
                        type="text"
                        value={tokenName}
                        onChange={(e) => {
                          setTokenName(e.target.value)
                          setTokenError(null)
                        }}
                        placeholder="GitHub Actions"
                        className="input"
                        maxLength={120}
                      />
                      <button
                        type="button"
                        onClick={handleCreateToken}
                        disabled={tokenBusy || !tokenName.trim()}
                        className="btn-primary px-3 disabled:opacity-50"
                      >
                        <Plus className="w-4 h-4" />
                      </button>
                    </div>
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
                                Created {token.created_at ? new Date(token.created_at).toLocaleDateString() : 'unknown'}
                              </p>
                              <p className="text-[10px] text-gray-400">
                                Last used {token.last_used_at ? new Date(token.last_used_at).toLocaleDateString() : 'never'}
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
            </div>

          </div>
        </form>
      )}
    </div>
  )
}
