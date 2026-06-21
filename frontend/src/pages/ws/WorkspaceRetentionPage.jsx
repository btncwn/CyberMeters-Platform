/**
 * WorkspaceRetentionPage — /ws/retention
 *
 * Sections:
 *  1. StorageUsageCard     — report count, storage used, retention period, cleanup status
 *  2. RetentionPolicyCard  — current policy summary with plan-based guidance
 *  3. RetentionSettingsCard — days selector + auto-cleanup toggle + save (PUT /api/workspaces/:id/retention)
 *  4. CleanupWarningModal  — triggered when reducing days or enabling cleanup
 *  5. StorageInsightsSection — lightweight derived insights from available data
 *
 * All sections gracefully handle missing data with empty states and skeleton loaders.
 * No backend modifications. UX only.
 */

import { useState, useEffect, useCallback } from 'react'
import {
  HardDrive, Clock, Trash2, ToggleLeft, ToggleRight,
  AlertTriangle, CheckCircle, RefreshCw, X, Info,
  TrendingUp, FileText, Shield,
} from 'lucide-react'
import { useWorkspace } from '../../hooks/useWorkspace'
import { api } from '../../api'
import WsPage, { NoWorkspaceSelected } from '../../components/WsPage'

// ── Constants ─────────────────────────────────────────────────────────────────

/** Plan retention ceilings — display only, no enforcement here */
const PLAN_RETENTION = [
  { plan: 'Free',       days: 30,     color: 'text-gray-500'   },
  { plan: 'Starter',    days: 90,     color: 'text-blue-600'   },
  { plan: 'Pro',        days: 365,    color: 'text-brand-600'  },
  { plan: 'Business',   days: 730,    color: 'text-amber-600'  },
  { plan: 'Enterprise', days: null,   color: 'text-purple-600' },
]

const RETENTION_OPTIONS = [
  { value: 30,   label: '30 days'    },
  { value: 60,   label: '60 days'    },
  { value: 90,   label: '90 days'    },
  { value: 180,  label: '180 days'   },
  { value: 365,  label: '1 year'     },
  { value: 730,  label: '2 years'    },
  { value: 1095, label: '3 years'    },
  { value: 2555, label: '7 years'    },
]

// ── Shared micro-components ───────────────────────────────────────────────────

/** Skeleton bar shown while loading */
function Skel({ className = '' }) {
  return <div className={`rounded-lg bg-gray-100 animate-pulse ${className}`} />
}

function StatItem({ label, value, sub, loading }) {
  return (
    <div className="flex flex-col gap-0.5">
      <span className="text-xs font-semibold text-gray-400 uppercase tracking-wider">{label}</span>
      {loading
        ? <Skel className="h-6 w-24 mt-1" />
        : <span className="text-lg font-bold text-gray-900">{value ?? '—'}</span>
      }
      {sub && !loading && <span className="text-xs text-gray-400">{sub}</span>}
    </div>
  )
}

function InlineBadge({ children, variant = 'neutral' }) {
  const cfg = {
    green:   'bg-green-50 text-green-700 border-green-100',
    red:     'bg-red-50 text-red-700 border-red-100',
    amber:   'bg-amber-50 text-amber-700 border-amber-100',
    neutral: 'bg-gray-50 text-gray-600 border-gray-100',
    brand:   'bg-brand-50 text-brand-700 border-brand-100',
  }[variant]
  return (
    <span className={`inline-flex items-center px-2 py-0.5 rounded-full text-xs font-semibold border ${cfg}`}>
      {children}
    </span>
  )
}

function SectionHeader({ icon: Icon, iconBg = 'bg-brand-50', iconColor = 'text-brand-600', title, subtitle, action }) {
  return (
    <div className="flex items-start justify-between gap-4 mb-5">
      <div className="flex items-start gap-3">
        <div className={`w-9 h-9 rounded-xl flex items-center justify-center flex-shrink-0 ${iconBg}`}>
          <Icon className={`w-4 h-4 ${iconColor}`} />
        </div>
        <div>
          <h2 className="text-sm font-bold text-gray-900">{title}</h2>
          {subtitle && <p className="text-xs text-gray-400 mt-0.5">{subtitle}</p>}
        </div>
      </div>
      {action && <div className="flex-shrink-0">{action}</div>}
    </div>
  )
}

// ── Cleanup Warning Modal ─────────────────────────────────────────────────────

function CleanupWarningModal({ open, onConfirm, onCancel, newDays, wasAutoCleanup, nowAutoCleanup, loading }) {
  if (!open) return null

  const reducingDays   = newDays !== null
  const enablingCleanup = !wasAutoCleanup && nowAutoCleanup

  return (
    <div className="fixed inset-0 z-[200] flex items-center justify-center bg-gray-900/40 px-4">
      <div className="w-full max-w-md bg-white rounded-2xl shadow-2xl border border-gray-100 overflow-hidden">
        {/* Header */}
        <div className="px-6 py-5 flex items-start gap-3 border-b border-amber-100 bg-amber-50">
          <div className="w-9 h-9 rounded-lg bg-amber-100 flex items-center justify-center flex-shrink-0">
            <AlertTriangle className="w-5 h-5 text-amber-600" />
          </div>
          <div className="flex-1 min-w-0">
            <h3 className="text-sm font-bold text-gray-900">Review your retention changes</h3>
            <p className="text-xs text-gray-500 mt-0.5">This may result in permanent data removal</p>
          </div>
          <button
            onClick={onCancel}
            disabled={loading}
            className="w-7 h-7 rounded-lg text-gray-400 hover:text-gray-600 hover:bg-amber-100 flex items-center justify-center flex-shrink-0"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Body */}
        <div className="px-6 py-5 space-y-3">
          {reducingDays && (
            <div className="flex items-start gap-2.5 p-3 rounded-xl bg-red-50 border border-red-100">
              <AlertTriangle className="w-4 h-4 text-red-500 flex-shrink-0 mt-0.5" />
              <p className="text-sm text-red-700">
                Reducing the retention period to <strong>{newDays} days</strong> means reports older than
                that may be <strong>permanently removed</strong> during the next cleanup cycle.
              </p>
            </div>
          )}
          {enablingCleanup && (
            <div className="flex items-start gap-2.5 p-3 rounded-xl bg-amber-50 border border-amber-100">
              <AlertTriangle className="w-4 h-4 text-amber-500 flex-shrink-0 mt-0.5" />
              <p className="text-sm text-amber-800">
                Enabling auto cleanup will automatically delete reports that exceed the configured
                retention period. <strong>This action cannot be automatically reversed</strong> once
                reports are purged.
              </p>
            </div>
          )}
          <p className="text-xs text-gray-400 leading-relaxed">
            Deleted reports cannot be recovered. Download any reports you need before confirming.
            Scan results and findings are not affected by retention settings.
          </p>
        </div>

        {/* Actions */}
        <div className="px-6 pb-5 flex justify-end gap-3">
          <button type="button" onClick={onCancel} disabled={loading} className="btn-secondary">
            Cancel
          </button>
          <button
            type="button"
            onClick={onConfirm}
            disabled={loading}
            className="inline-flex items-center gap-2 px-4 py-2 rounded-xl text-sm font-semibold bg-amber-600 hover:bg-amber-700 text-white transition-colors disabled:opacity-50"
          >
            {loading ? <><RefreshCw className="w-4 h-4 animate-spin" />Saving…</> : 'Confirm & save'}
          </button>
        </div>
      </div>
    </div>
  )
}

// ── 1. Storage Usage Card ─────────────────────────────────────────────────────

function StorageUsageCard({ wsId }) {
  const [data,    setData]    = useState(null)
  const [loading, setLoading] = useState(true)
  const [error,   setError]   = useState(null)

  useEffect(() => {
    if (!wsId) return
    setLoading(true)
    api.getWorkspaceStorage(wsId)
      .then(d => setData(d))
      .catch(e => setError(e.message || 'Unable to load storage data'))
      .finally(() => setLoading(false))
  }, [wsId])

  function fmtBytes(mb) {
    if (mb === null || mb === undefined) return '—'
    if (mb < 1) return `${Math.round(mb * 1024)} KB`
    if (mb >= 1024) return `${(mb / 1024).toFixed(1)} GB`
    return `${mb.toFixed(1)} MB`
  }

  const noData = !loading && !error && !data

  return (
    <div className="card p-6">
      <SectionHeader
        icon={HardDrive}
        title="Storage Usage"
        subtitle="Report storage consumed by this workspace"
        action={
          !loading && (
            <button
              onClick={() => { setLoading(true); setError(null); api.getWorkspaceStorage(wsId).then(setData).catch(e => setError(e.message)).finally(() => setLoading(false)) }}
              className="w-7 h-7 rounded-lg text-gray-400 hover:text-gray-600 hover:bg-gray-100 flex items-center justify-center transition-colors"
              title="Refresh"
            >
              <RefreshCw className="w-3.5 h-3.5" />
            </button>
          )
        }
      />

      {error && (
        <div className="flex items-center gap-2.5 px-4 py-3 rounded-xl bg-red-50 border border-red-100 text-sm text-red-700">
          <AlertTriangle className="w-4 h-4 flex-shrink-0" />
          {error}
        </div>
      )}

      {noData && !error && (
        <div className="flex flex-col items-center py-8 text-center gap-3">
          <div className="w-12 h-12 rounded-2xl bg-gray-50 flex items-center justify-center">
            <HardDrive className="w-6 h-6 text-gray-300" />
          </div>
          <p className="text-sm font-medium text-gray-500">Storage metrics unavailable</p>
          <p className="text-xs text-gray-400 max-w-xs">
            Storage data will appear once reports have been generated for this workspace.
          </p>
        </div>
      )}

      {(loading || data) && (
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-6">
          <StatItem label="Reports stored"  value={data?.report_count?.toLocaleString()}                    loading={loading} />
          <StatItem label="Storage used"    value={fmtBytes(data?.storage_mb)}                              loading={loading} />
          <StatItem label="Retention"       value={data?.retention_days ? `${data.retention_days} days` : '—'} loading={loading} />
          <StatItem
            label="Auto cleanup"
            loading={loading}
            value={
              !loading && data && (
                <InlineBadge variant={data.auto_cleanup ? 'green' : 'neutral'}>
                  {data.auto_cleanup ? 'Enabled' : 'Disabled'}
                </InlineBadge>
              )
            }
          />
        </div>
      )}
    </div>
  )
}

// ── 2. Retention Policy Card ──────────────────────────────────────────────────

function RetentionPolicyCard({ wsId }) {
  const [data,    setData]    = useState(null)
  const [loading, setLoading] = useState(true)
  const [error,   setError]   = useState(null)

  useEffect(() => {
    if (!wsId) return
    setLoading(true)
    api.getWorkspaceRetention(wsId)
      .then(d => setData(d))
      .catch(e => setError(e.message || 'Unable to load retention policy'))
      .finally(() => setLoading(false))
  }, [wsId])

  const noData = !loading && !error && !data

  return (
    <div className="card p-6">
      <SectionHeader
        icon={Clock}
        iconBg="bg-blue-50"
        iconColor="text-blue-600"
        title="Current Retention Policy"
        subtitle="Your active report lifecycle settings"
      />

      {error && (
        <div className="flex items-center gap-2.5 px-4 py-3 rounded-xl bg-red-50 border border-red-100 text-sm text-red-700">
          <AlertTriangle className="w-4 h-4 flex-shrink-0" />
          {error}
        </div>
      )}

      {noData && !error && (
        <div className="flex flex-col items-center py-8 text-center gap-3">
          <div className="w-12 h-12 rounded-2xl bg-gray-50 flex items-center justify-center">
            <Clock className="w-6 h-6 text-gray-300" />
          </div>
          <p className="text-sm font-medium text-gray-500">No retention policy configured</p>
          <p className="text-xs text-gray-400 max-w-xs">
            Configure a retention policy below to control how long reports are stored.
          </p>
        </div>
      )}

      {(loading || data) && (
        <div className="space-y-5">
          {/* Active policy summary */}
          <div className="flex items-center gap-4 p-4 rounded-xl bg-gray-50 border border-gray-100">
            {loading ? (
              <div className="flex gap-4 w-full">
                <Skel className="h-10 w-10 rounded-lg" />
                <div className="flex-1 space-y-2">
                  <Skel className="h-4 w-32" />
                  <Skel className="h-3 w-48" />
                </div>
              </div>
            ) : (
              <>
                <div className="w-10 h-10 rounded-lg bg-brand-50 flex items-center justify-center flex-shrink-0">
                  <Clock className="w-5 h-5 text-brand-600" />
                </div>
                <div className="flex-1 min-w-0">
                  <p className="text-sm font-bold text-gray-900">
                    {data?.retention_days ? `${data.retention_days}-day retention` : 'Not configured'}
                  </p>
                  <p className="text-xs text-gray-400 mt-0.5">
                    Auto cleanup is{' '}
                    <span className={data?.auto_cleanup ? 'text-green-600 font-medium' : 'text-gray-500'}>
                      {data?.auto_cleanup ? 'enabled' : 'disabled'}
                    </span>
                    {data?.plan ? ` · Plan: ${data.plan}` : ''}
                  </p>
                </div>
                <InlineBadge variant={data?.auto_cleanup ? 'green' : 'neutral'}>
                  {data?.auto_cleanup ? 'Active' : 'Manual'}
                </InlineBadge>
              </>
            )}
          </div>

          {/* Plan guidance table */}
          <div>
            <p className="text-xs font-semibold text-gray-400 uppercase tracking-wider mb-2">
              Plan retention guide
            </p>
            <div className="overflow-hidden rounded-xl border border-gray-100">
              <table className="w-full text-sm">
                <thead>
                  <tr className="bg-gray-50 border-b border-gray-100">
                    <th className="px-4 py-2.5 text-left text-xs font-semibold text-gray-500">Plan</th>
                    <th className="px-4 py-2.5 text-left text-xs font-semibold text-gray-500">Max retention</th>
                  </tr>
                </thead>
                <tbody>
                  {PLAN_RETENTION.map(({ plan, days, color }) => (
                    <tr
                      key={plan}
                      className={`border-b border-gray-50 last:border-0 transition-colors ${
                        data?.plan?.toLowerCase().includes(plan.toLowerCase()) ? 'bg-brand-50/40' : 'hover:bg-gray-50/50'
                      }`}
                    >
                      <td className={`px-4 py-2.5 font-semibold ${color}`}>{plan}</td>
                      <td className="px-4 py-2.5 text-gray-600">
                        {days ? `${days} days` : 'Unlimited'}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}

// ── 3. Retention Settings Card ────────────────────────────────────────────────

function RetentionSettingsCard({ wsId, onSaved }) {
  const [current,    setCurrent]    = useState(null)   // fetched policy
  const [loading,    setLoading]    = useState(true)
  const [loadError,  setLoadError]  = useState(null)

  const [days,       setDays]       = useState(365)
  const [cleanup,    setCleanup]    = useState(false)

  const [dirty,      setDirty]      = useState(false)
  const [saving,     setSaving]     = useState(false)
  const [saveOk,     setSaveOk]     = useState(false)
  const [saveErr,    setSaveErr]    = useState(null)

  const [warnOpen,   setWarnOpen]   = useState(false)

  const load = useCallback(() => {
    if (!wsId) return
    setLoading(true)
    setLoadError(null)
    api.getWorkspaceRetention(wsId)
      .then(d => {
        setCurrent(d)
        setDays(d?.retention_days ?? 365)
        setCleanup(d?.auto_cleanup ?? false)
        setDirty(false)
      })
      .catch(e => setLoadError(e.message || 'Unable to load settings'))
      .finally(() => setLoading(false))
  }, [wsId])

  useEffect(() => { load() }, [load])

  function handleChange(newDays, newCleanup) {
    setDays(newDays)
    setCleanup(newCleanup)
    setSaveOk(false)
    setSaveErr(null)
    setDirty(true)
  }

  function handleSave() {
    const reducingDays    = current?.retention_days && days < current.retention_days
    const enablingCleanup = !current?.auto_cleanup && cleanup
    if (reducingDays || enablingCleanup) {
      setWarnOpen(true)
    } else {
      doSave()
    }
  }

  async function doSave() {
    setSaving(true)
    setSaveErr(null)
    setWarnOpen(false)
    try {
      await api.updateWorkspaceRetention(wsId, { retention_days: days, auto_cleanup: cleanup })
      setSaveOk(true)
      setDirty(false)
      setCurrent({ ...current, retention_days: days, auto_cleanup: cleanup })
      if (onSaved) onSaved()
    } catch (e) {
      setSaveErr(e.message || 'Save failed. Please try again.')
    } finally {
      setSaving(false)
    }
  }

  return (
    <div className="card p-6">
      <SectionHeader
        icon={Shield}
        iconBg="bg-amber-50"
        iconColor="text-amber-600"
        title="Retention Controls"
        subtitle="Configure how long reports are stored and when cleanup runs"
      />

      {loadError && (
        <div className="flex items-center gap-2.5 px-4 py-3 rounded-xl bg-red-50 border border-red-100 text-sm text-red-700 mb-5">
          <AlertTriangle className="w-4 h-4 flex-shrink-0" />
          {loadError}
          <button onClick={load} className="ml-auto text-xs underline">Retry</button>
        </div>
      )}

      {loading ? (
        <div className="space-y-5">
          <Skel className="h-14 w-full rounded-xl" />
          <Skel className="h-14 w-full rounded-xl" />
          <Skel className="h-10 w-32 rounded-xl" />
        </div>
      ) : (
        <div className="space-y-5">
          {/* Retention days selector */}
          <div>
            <label className="block text-xs font-semibold text-gray-500 mb-1.5">
              Retention period
            </label>
            <select
              value={days}
              onChange={e => handleChange(Number(e.target.value), cleanup)}
              className="input w-full sm:w-64"
              disabled={saving}
            >
              {RETENTION_OPTIONS.map(opt => (
                <option key={opt.value} value={opt.value}>{opt.label}</option>
              ))}
            </select>
            <p className="text-xs text-gray-400 mt-1.5">
              Reports older than this period may be removed during cleanup.
            </p>
          </div>

          {/* Auto cleanup toggle */}
          <div className="flex items-start justify-between gap-4 p-4 rounded-xl border border-gray-100 hover:border-gray-200 transition-colors">
            <div className="flex-1 min-w-0">
              <p className="text-sm font-semibold text-gray-900">Auto cleanup</p>
              <p className="text-xs text-gray-400 mt-0.5">
                Automatically remove reports that exceed the retention period.
                When disabled, reports are kept indefinitely regardless of the period setting.
              </p>
            </div>
            <button
              type="button"
              onClick={() => handleChange(days, !cleanup)}
              disabled={saving}
              className="flex-shrink-0 mt-0.5"
              aria-label={cleanup ? 'Disable auto cleanup' : 'Enable auto cleanup'}
            >
              {cleanup
                ? <ToggleRight className="w-9 h-9 text-brand-600" />
                : <ToggleLeft  className="w-9 h-9 text-gray-300" />
              }
            </button>
          </div>

          {/* Warning copy — always visible */}
          <div className="flex items-start gap-2.5 px-4 py-3 rounded-xl bg-amber-50 border border-amber-100">
            <AlertTriangle className="w-4 h-4 text-amber-500 flex-shrink-0 mt-0.5" />
            <p className="text-xs text-amber-800 leading-relaxed">
              Reports older than the configured retention period may be permanently removed.
              Download any reports you need before enabling auto cleanup.
            </p>
          </div>

          {/* Save feedback */}
          {saveOk && (
            <div className="flex items-center gap-2 px-4 py-3 rounded-xl bg-green-50 border border-green-100 text-sm text-green-700">
              <CheckCircle className="w-4 h-4 flex-shrink-0" />
              Retention settings saved successfully.
            </div>
          )}
          {saveErr && (
            <div className="flex items-center gap-2 px-4 py-3 rounded-xl bg-red-50 border border-red-100 text-sm text-red-700">
              <AlertTriangle className="w-4 h-4 flex-shrink-0" />
              {saveErr}
            </div>
          )}

          {/* Save button */}
          <div className="flex items-center gap-3">
            <button
              type="button"
              onClick={handleSave}
              disabled={!dirty || saving}
              className="btn-primary disabled:opacity-50"
            >
              {saving
                ? <><RefreshCw className="w-4 h-4 animate-spin" />Saving…</>
                : 'Save settings'
              }
            </button>
            {dirty && (
              <button
                type="button"
                onClick={() => { setDays(current?.retention_days ?? 365); setCleanup(current?.auto_cleanup ?? false); setDirty(false); setSaveOk(false); setSaveErr(null) }}
                disabled={saving}
                className="text-sm text-gray-400 hover:text-gray-600 transition-colors"
              >
                Discard
              </button>
            )}
          </div>
        </div>
      )}

      <CleanupWarningModal
        open={warnOpen}
        onConfirm={doSave}
        onCancel={() => setWarnOpen(false)}
        newDays={current?.retention_days && days < current.retention_days ? days : null}
        wasAutoCleanup={current?.auto_cleanup}
        nowAutoCleanup={cleanup}
        loading={saving}
      />
    </div>
  )
}

// ── 5. Storage Insights Section ───────────────────────────────────────────────

function StorageInsightsSection({ wsId }) {
  const [storage,   setStorage]   = useState(null)
  const [retention, setRetention] = useState(null)
  const [loading,   setLoading]   = useState(true)

  useEffect(() => {
    if (!wsId) return
    Promise.allSettled([
      api.getWorkspaceStorage(wsId),
      api.getWorkspaceRetention(wsId),
    ]).then(([sRes, rRes]) => {
      if (sRes.status === 'fulfilled') setStorage(sRes.value)
      if (rRes.status === 'fulfilled') setRetention(rRes.value)
    }).finally(() => setLoading(false))
  }, [wsId])

  if (loading) {
    return (
      <div className="card p-6">
        <SectionHeader icon={Info} iconBg="bg-gray-50" iconColor="text-gray-400" title="Storage Insights" />
        <div className="space-y-2.5">
          <Skel className="h-10 w-full rounded-xl" />
          <Skel className="h-10 w-4/5 rounded-xl" />
        </div>
      </div>
    )
  }

  // Build insights from available data only
  const insights = []

  if (storage) {
    const mb = storage.storage_mb ?? 0
    if (mb < 100)  insights.push({ icon: CheckCircle, color: 'text-green-600', bg: 'bg-green-50', text: 'Storage usage is within typical plan limits.' })
    if (mb > 500)  insights.push({ icon: AlertTriangle, color: 'text-amber-600', bg: 'bg-amber-50', text: 'Storage usage is high. Consider downloading and archiving older reports.' })

    if (storage.report_count > 0 && retention?.retention_days) {
      // Rough estimate: assume linear distribution of reports
      const estimatedOld = Math.round(storage.report_count * 0.15)
      if (estimatedOld > 0 && retention.auto_cleanup) {
        insights.push({
          icon: Trash2,
          color: 'text-amber-600',
          bg: 'bg-amber-50',
          text: `Auto cleanup may remove approximately ${estimatedOld} older report${estimatedOld === 1 ? '' : 's'} based on your retention policy.`,
        })
      }
    }

    if (storage.report_count === 0) {
      insights.push({ icon: FileText, color: 'text-gray-400', bg: 'bg-gray-50', text: 'No reports stored yet. Retention settings will apply once reports are generated.' })
    }
  }

  if (retention) {
    if (!retention.auto_cleanup) {
      insights.push({ icon: Info, color: 'text-blue-600', bg: 'bg-blue-50', text: 'Auto cleanup is disabled. Reports will accumulate until manually managed.' })
    }
    if (retention.retention_days >= 730) {
      insights.push({ icon: TrendingUp, color: 'text-brand-600', bg: 'bg-brand-50', text: 'Long retention periods support compliance and historical trend analysis.' })
    }
  }

  if (insights.length === 0) return null

  return (
    <div className="card p-6">
      <SectionHeader
        icon={Info}
        iconBg="bg-gray-50"
        iconColor="text-gray-500"
        title="Storage Insights"
        subtitle="Observations based on your current configuration"
      />
      <div className="space-y-2.5">
        {insights.map((ins, i) => {
          const Icon = ins.icon
          return (
            <div key={i} className={`flex items-start gap-3 px-4 py-3 rounded-xl border ${ins.bg} border-transparent`}>
              <Icon className={`w-4 h-4 flex-shrink-0 mt-0.5 ${ins.color}`} />
              <p className="text-sm text-gray-700 leading-relaxed">{ins.text}</p>
            </div>
          )
        })}
      </div>
    </div>
  )
}

// ── Page ──────────────────────────────────────────────────────────────────────

export default function WorkspaceRetentionPage() {
  const { wsId, wsName } = useWorkspace()

  if (!wsId) {
    return (
      <div className="flex">
        <div className="flex-1 min-w-0">
          <div className="max-w-screen-xl mx-auto px-6 py-8">
            <NoWorkspaceSelected />
          </div>
        </div>
      </div>
    )
  }

  return (
    <WsPage wsId={wsId} wsName={wsName}>
      {/* Page header */}
      <div className="mb-8">
        <h1 className="text-2xl font-bold text-gray-900">Retention Controls</h1>
        <p className="text-sm text-gray-400 mt-0.5">
          Manage report storage, configure retention periods, and control automatic cleanup.
        </p>
      </div>

      <div className="space-y-6">
        <StorageUsageCard wsId={wsId} />
        <RetentionPolicyCard wsId={wsId} />
        <RetentionSettingsCard wsId={wsId} />
        <StorageInsightsSection wsId={wsId} />
      </div>
    </WsPage>
  )
}
