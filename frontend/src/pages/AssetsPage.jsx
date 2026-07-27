import { parseServerDate } from '../utils/dates'
import CasesQueue from '../components/CasesQueue'
import { useState, useEffect, useCallback } from 'react'
import { Link } from 'react-router-dom'
import {
  RefreshCw, Server, AlertTriangle, Globe, Cloud,
  Shield, Activity, X, ChevronRight, Layers, UserCheck,
  CheckCircle, Clock, Wrench,
} from 'lucide-react'
import { api } from '../api'
import Spinner from '../components/Spinner'
import StatCard from '../components/StatCard'
import AttackSurfaceAssurance from '../components/AttackSurfaceAssurance'

// ── Formatters ─────────────────────────────────────────────────────────────────

function fmtDate(iso) {
  if (!iso) return '—'
  return parseServerDate(iso).toLocaleDateString(undefined, { dateStyle: 'medium' })
}

function fmtDateTime(iso) {
  if (!iso) return '—'
  return parseServerDate(iso).toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' })
}

// ── Badges ─────────────────────────────────────────────────────────────────────

function RiskBadge({ level }) {
  if (!level) return <span className="text-gray-300 text-xs">—</span>
  const cls = {
    critical: 'badge-critical',
    high:     'badge-high',
    medium:   'badge-medium',
    low:      'badge-low',
  }[level] || 'badge-unknown' // M5.e: unknown severity is UNKNOWN, never low-risk blue
  return <span className={cls}>{level}</span>
}

function StatusPill({ status }) {
  if (status === 'active')
    return (
      <span className="inline-flex items-center px-2 py-0.5 rounded-full text-xs font-semibold bg-green-100 text-green-700">
        Legacy active
      </span>
    )
  return (
    <span className="inline-flex items-center px-2 py-0.5 rounded-full text-xs font-semibold bg-gray-100 text-gray-500">
      Legacy inactive
    </span>
  )
}

const TYPE_META = {
  root_domain:      { label: 'Root Domain',      cls: 'bg-brand-50 text-brand-700'   },
  subdomain:        { label: 'Subdomain',         cls: 'bg-blue-50 text-blue-700'     },
  exposed_service:  { label: 'Exposed Service',   cls: 'bg-amber-50 text-amber-700'   },
  cloud_storage:    { label: 'Cloud Storage',     cls: 'bg-purple-50 text-purple-700' },
}

function TypeBadge({ type }) {
  const { label = type, cls = 'bg-gray-100 text-gray-500' } = TYPE_META[type] || {}
  return (
    <span className={`inline-flex items-center px-2 py-0.5 rounded-full text-xs font-semibold ${cls}`}>
      {label}
    </span>
  )
}

const CASE_STATUS_META = {
  open: { label: 'Open', cls: 'bg-red-50 text-red-700 border-red-100' },
  triage: { label: 'Triage', cls: 'bg-amber-50 text-amber-700 border-amber-100' },
  owner_assigned: { label: 'Owner assigned', cls: 'bg-blue-50 text-blue-700 border-blue-100' },
  remediation_in_progress: { label: 'In progress', cls: 'bg-blue-50 text-blue-700 border-blue-100' },
  verification_requested: { label: 'Verification requested', cls: 'bg-purple-50 text-purple-700 border-purple-100' },
  verifying: { label: 'Verifying', cls: 'bg-purple-50 text-purple-700 border-purple-100' },
  verification_failed: { label: 'Fix not verified', cls: 'bg-amber-50 text-amber-700 border-amber-100' },
  resolved: { label: 'Resolved', cls: 'bg-green-50 text-green-700 border-green-100' },
  reopened: { label: 'Reopened', cls: 'bg-red-50 text-red-700 border-red-100' },
  risk_accepted: { label: 'Risk accepted', cls: 'bg-gray-50 text-gray-600 border-gray-200' },
  false_positive: { label: 'False positive', cls: 'bg-gray-50 text-gray-600 border-gray-200' },
  closed: { label: 'Closed', cls: 'bg-gray-50 text-gray-600 border-gray-200' },
}

function CaseStatusPill({ status }) {
  const meta = CASE_STATUS_META[status] || { label: status, cls: 'bg-gray-50 text-gray-600 border-gray-200' }
  return <span className={`inline-flex items-center rounded-full border px-2 py-0.5 text-xs font-semibold ${meta.cls}`}>{meta.label}</span>
}

function ManagedCasesPanel({ workspaceId }) {
  const [cases, setCases] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const [busy, setBusy] = useState(null)
  const [owners, setOwners] = useState({})

  const loadCases = useCallback(async () => {
    if (!workspaceId) return
    setLoading(true)
    setError(null)
    try {
      const data = await api.getManagedCases(workspaceId, { case_type: 'asm_exposure', limit: 20 })
      setCases(data.cases || [])
    } catch (e) {
      setError(e.message || 'Could not load managed cases.')
    } finally {
      setLoading(false)
    }
  }, [workspaceId])

  useEffect(() => { loadCases() }, [loadCases])

  async function assignOwner(item) {
    const owner = (owners[item.id] || '').trim()
    if (!owner) return
    setBusy(item.id)
    try {
      await api.assignManagedCaseOwner(workspaceId, item.id, { owner_type: 'unknown', owner_ref: owner })
      setOwners(prev => ({ ...prev, [item.id]: '' }))
      await loadCases()
    } catch (e) {
      setError(e.message || 'Could not assign owner.')
    } finally {
      setBusy(null)
    }
  }

  async function transition(item, status, action) {
    setBusy(item.id)
    try {
      await api.transitionManagedCase(workspaceId, item.id, { status, action })
      await loadCases()
    } catch (e) {
      setError(e.message || 'Could not update case.')
    } finally {
      setBusy(null)
    }
  }

  if (loading) return null
  if (!error && cases.length === 0) return null

  return (
    <div className="card p-0 overflow-hidden">
      <div className="flex items-center justify-between gap-3 px-5 py-4 border-b border-gray-100">
        <div className="flex items-center gap-3">
          <div className="w-8 h-8 rounded-xl bg-brand-50 flex items-center justify-center">
            <Wrench className="w-4 h-4 text-brand-600" />
          </div>
          <div>
            <h2 className="text-sm font-bold text-gray-900">Managed Cases</h2>
            <p className="text-xs text-gray-400">Customer-owned fixes with CyberMeters verification.</p>
          </div>
        </div>
        <button onClick={loadCases} className="btn-secondary text-xs">
          <RefreshCw className="w-3.5 h-3.5" />
          Refresh
        </button>
      </div>
      {error && (
        <div className="mx-5 mt-4 rounded-lg border border-red-100 bg-red-50 px-3 py-2 text-xs text-red-700">
          {error}
        </div>
      )}
      <div className="divide-y divide-gray-100">
        {cases.map(item => (
          <div key={item.id} className="px-5 py-4">
            <div className="flex flex-col lg:flex-row lg:items-start justify-between gap-4">
              <div className="min-w-0 space-y-2">
                <div className="flex items-center gap-2 flex-wrap">
                  <RiskBadge level={item.severity} />
                  <CaseStatusPill status={item.status} />
                  {item.reopened_count > 0 && (
                    <span className="inline-flex items-center rounded-full bg-red-50 px-2 py-0.5 text-xs font-semibold text-red-700">
                      Reopened {item.reopened_count}x
                    </span>
                  )}
                </div>
                <div>
                  <p className="text-sm font-bold text-gray-900">{item.evidence?.finding?.title || item.finding_id}</p>
                  <p className="mono text-xs text-gray-500 mt-0.5">{item.asset_ref || item.domain}</p>
                </div>
                <p className="text-xs text-gray-500 leading-relaxed max-w-3xl">
                  {item.evidence?.finding?.description || item.recommended_actions?.[0]?.action || 'Review this externally visible exposure and confirm the fix when complete.'}
                </p>
                <div className="flex items-center gap-4 text-xs text-gray-400">
                  <span className="inline-flex items-center gap-1"><Clock className="w-3.5 h-3.5" /> {item.age_hours ?? 0}h open</span>
                  {item.owner_ref && <span className="inline-flex items-center gap-1"><UserCheck className="w-3.5 h-3.5" /> {item.owner_ref}</span>}
                  {item.last_verified_at && <span className="inline-flex items-center gap-1"><CheckCircle className="w-3.5 h-3.5" /> checked {fmtDate(item.last_verified_at)}</span>}
                </div>
              </div>
              <div className="w-full lg:w-72 flex-shrink-0 space-y-2">
                {!item.owner_ref && (
                  <div className="flex gap-2">
                    <input
                      value={owners[item.id] || ''}
                      onChange={e => setOwners(prev => ({ ...prev, [item.id]: e.target.value }))}
                      placeholder="Owner or team"
                      className="input text-sm min-w-0"
                    />
                    <button onClick={() => assignOwner(item)} disabled={busy === item.id || !(owners[item.id] || '').trim()} className="btn-secondary text-xs disabled:opacity-50">
                      Assign
                    </button>
                  </div>
                )}
                {item.status === 'owner_assigned' && (
                  <button onClick={() => transition(item, 'remediation_in_progress', 'remediation_started')} disabled={busy === item.id} className="btn-secondary w-full justify-center text-xs disabled:opacity-50">
                    Start remediation
                  </button>
                )}
                {(item.status === 'remediation_in_progress' || item.status === 'verification_failed') && (
                  <button onClick={() => transition(item, 'verification_requested', 'fix_completed')} disabled={busy === item.id} className="btn-primary w-full justify-center text-xs disabled:opacity-50">
                    Mark fix completed
                  </button>
                )}
                {item.status === 'verification_requested' && (
                  <p className="rounded-lg bg-purple-50 px-3 py-2 text-xs text-purple-700">CyberMeters will verify this on the next Cyber MOT.</p>
                )}
                {item.status === 'resolved' && (
                  <p className="rounded-lg bg-green-50 px-3 py-2 text-xs text-green-700">Verified resolved by CyberMeters.</p>
                )}
              </div>
            </div>
          </div>
        ))}
      </div>
    </div>
  )
}

// ── Summary card ───────────────────────────────────────────────────────────────

function SummaryCard({ icon: Icon, label, value, iconCls = 'text-brand-600', bgCls = 'bg-brand-50' }) {
  return (
    <div className="card p-4 flex items-center gap-3">
      <div className={`w-9 h-9 rounded-xl ${bgCls} flex items-center justify-center flex-shrink-0`}>
        <Icon className={`w-4 h-4 ${iconCls}`} />
      </div>
      <div className="min-w-0">
        <div className="text-2xl font-bold text-gray-900 leading-none">{value ?? '—'}</div>
        <div className="text-xs text-gray-400 mt-0.5 truncate">{label}</div>
      </div>
    </div>
  )
}

// ── Asset Detail Panel ─────────────────────────────────────────────────────────

function AssetDetailPanel({ workspaceId, assetId, onClose }) {
  const [data,    setData]    = useState(null)
  const [loading, setLoading] = useState(true)
  const [error,   setError]   = useState(null)

  useEffect(() => {
    let cancelled = false
    setLoading(true)
    setError(null)
    api.getWorkspaceAsset(workspaceId, assetId)
      .then(d  => { if (!cancelled) { setData(d);        setLoading(false) } })
      .catch(e => { if (!cancelled) { setError(e.message); setLoading(false) } })
    return () => { cancelled = true }
  }, [workspaceId, assetId])

  // Parse IP array stored as JSON string
  function parseIps(raw) {
    try { const v = JSON.parse(raw); return Array.isArray(v) ? v : [] }
    catch { return [] }
  }

  return (
    <div className="fixed inset-0 z-50 flex justify-end">
      <div className="absolute inset-0 bg-black/20" onClick={onClose} />
      <div className="relative bg-white shadow-2xl w-full max-w-lg flex flex-col overflow-y-auto">

        {/* Header */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-gray-100 sticky top-0 bg-white z-10">
          <h2 className="text-base font-semibold text-gray-900">Asset Detail</h2>
          <button
            onClick={onClose}
            className="w-8 h-8 flex items-center justify-center rounded-lg hover:bg-gray-100 text-gray-400 transition-colors"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        <div className="p-6 flex-1 space-y-6">
          {loading && <div className="flex justify-center py-12"><Spinner /></div>}
          {error && (
            <div className="px-4 py-3 bg-red-50 border border-red-100 rounded-xl text-sm text-red-700">{error}</div>
          )}

          {data && (
            <>
              {/* Hostname */}
              <div>
                <div className="label mb-1">Hostname</div>
                <div className="mono text-sm font-semibold text-gray-900 break-all">{data.asset.hostname}</div>
              </div>

              <AttackSurfaceAssurance presentations={data.attack_surface_assurance || data.asset.attack_surface_assurance} />

              {/* Grid */}
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <div className="label mb-1">Type</div>
                  <TypeBadge type={data.asset.asset_type} />
                </div>
                <div>
                  <div className="label mb-1">Status</div>
                  <StatusPill status={data.asset.status} />
                </div>
                <div>
                  <div className="label mb-1">Source</div>
                  <span className="text-xs text-gray-600">{data.asset.source || '—'}</span>
                </div>
                <div>
                  <div className="label mb-1">Risk</div>
                  <RiskBadge level={data.asset.risk_level} />
                </div>
                <div>
                  <div className="label mb-1">First Seen</div>
                  <span className="text-xs text-gray-600">{fmtDate(data.asset.first_seen)}</span>
                </div>
                <div>
                  <div className="label mb-1">Last Seen</div>
                  <span className="text-xs text-gray-600">{fmtDate(data.asset.last_seen)}</span>
                </div>
                {data.asset.cloud_provider && (
                  <div className="col-span-2">
                    <div className="label mb-1">Cloud Provider</div>
                    <span className="text-xs text-gray-600">{data.asset.cloud_provider}</span>
                  </div>
                )}
                {data.asset.cname && (
                  <div className="col-span-2">
                    <div className="label mb-1">CNAME</div>
                    <span className="mono text-xs text-gray-600">{data.asset.cname}</span>
                  </div>
                )}
                {data.asset.redirect_to && (
                  <div className="col-span-2">
                    <div className="label mb-1">Redirects To</div>
                    <span className="mono text-xs text-gray-600 break-all">{data.asset.redirect_to}</span>
                  </div>
                )}
                {(() => {
                  const ips = parseIps(data.asset.ip_addresses)
                  if (!ips.length) return null
                  return (
                    <div className="col-span-2">
                      <div className="label mb-1">IP Addresses</div>
                      <div className="flex flex-wrap gap-1">
                        {ips.map(ip => (
                          <span key={ip} className="mono text-xs bg-gray-50 border border-gray-200 rounded px-1.5 py-0.5">
                            {ip}
                          </span>
                        ))}
                      </div>
                    </div>
                  )
                })()}
              </div>

              {/* Events */}
              {data.events.length > 0 && (
                <div>
                  <div className="label mb-3">Recent Events ({data.events.length})</div>
                  <div className="space-y-2">
                    {data.events.map(ev => (
                      <div key={ev.id} className="flex items-start gap-3 px-3 py-2.5 bg-gray-50 rounded-xl">
                        <div className="w-1.5 h-1.5 rounded-full bg-brand-400 mt-1.5 flex-shrink-0" />
                        <div className="min-w-0 flex-1">
                          <div className="text-xs font-medium text-gray-700 capitalize">
                            {ev.event_type.replace(/_/g, ' ')}
                          </div>
                          {ev.description && (
                            <div className="text-xs text-gray-400 mt-0.5">{ev.description}</div>
                          )}
                          <div className="text-[10px] text-gray-400 mt-1">{fmtDateTime(ev.created_at)}</div>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}
              {data.events.length === 0 && (
                <p className="text-xs text-gray-400">No events recorded for this asset.</p>
              )}
            </>
          )}
        </div>
      </div>
    </div>
  )
}

// ── Timeline table ─────────────────────────────────────────────────────────────

const TIMELINE_COLS = [
  { key: 'new_asset_discovered',   label: 'New'       },
  { key: 'asset_reappeared',       label: 'Reappeared'},
  { key: 'asset_no_longer_seen',   label: 'Removal event' },
  { key: 'takeover_risk_detected', label: 'Takeover'  },
  { key: 'wildcard_dns_detected',  label: 'Wildcard'  },
  { key: 'cloud_storage_detected', label: 'Cloud'     },
]

function Timeline({ rows }) {
  if (!rows || rows.length === 0) {
    return (
      <p className="text-sm text-gray-400 py-8 text-center">
        No timeline data yet. Run a scan to start tracking asset changes.
      </p>
    )
  }

  const sorted = [...rows].sort((a, b) => b.day.localeCompare(a.day)).slice(0, 30)

  return (
    <div className="overflow-x-auto">
      <table className="data-table w-full">
        <thead>
          <tr>
            <th>Date</th>
            {TIMELINE_COLS.map(c => <th key={c.key} className="text-center">{c.label}</th>)}
          </tr>
        </thead>
        <tbody>
          {sorted.map(row => (
            <tr key={row.day}>
              <td className="mono text-xs">{row.day}</td>
              {TIMELINE_COLS.map(c => (
                <td key={c.key} className="text-center">
                  {row[c.key] > 0
                    ? (
                      <span className="inline-flex items-center justify-center w-6 h-6 rounded-full bg-brand-50 text-brand-700 text-xs font-semibold">
                        {row[c.key]}
                      </span>
                    )
                    : <span className="text-gray-200 text-xs">—</span>
                  }
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

// ── Filter button ──────────────────────────────────────────────────────────────

function FilterBtn({ active, onClick, children }) {
  return (
    <button
      onClick={onClick}
      className={active
        ? 'px-3 py-1 rounded-lg text-xs font-semibold bg-brand-600 text-white transition-colors'
        : 'px-3 py-1 rounded-lg text-xs font-semibold bg-white border border-gray-200 text-gray-600 hover:border-brand-300 transition-colors'
      }
    >
      {children}
    </button>
  )
}

// ── Page ───────────────────────────────────────────────────────────────────────

export default function AssetsPage() {
  const workspaceId   = localStorage.getItem('cybermeters_workspace_id')
  const workspaceName = localStorage.getItem('cybermeters_workspace_name')

  const [summary,      setSummary]      = useState(null)
  const [assets,       setAssets]       = useState([])
  const [assurance,    setAssurance]    = useState([])
  const [assuranceCoverage, setAssuranceCoverage] = useState(null)
  const [timeline,     setTimeline]     = useState([])
  const [loading,      setLoading]      = useState(true)
  const [refreshing,   setRefreshing]   = useState(false)
  const [error,        setError]        = useState(null)
  const [statusFilter, setStatusFilter] = useState('all')
  const [typeFilter,   setTypeFilter]   = useState('all')
  const [selectedId,   setSelectedId]   = useState(null)

  const load = useCallback(async (silent = false) => {
    if (!workspaceId) { setLoading(false); return }
    if (!silent) setLoading(true); else setRefreshing(true)
    setError(null)
    try {
      const [sumData, assetsData, timelineData] = await Promise.all([
        api.getWorkspaceAssetsSummary(workspaceId),
        api.getWorkspaceAssets(workspaceId),
        api.getWorkspaceAssetsTimeline(workspaceId),
      ])
      setSummary(sumData)
      setAssets(assetsData.assets || [])
      setAssurance(assetsData.attack_surface_assurance || [])
      setAssuranceCoverage(assetsData.attack_surface_assurance_coverage || null)
      setTimeline(timelineData.timeline || [])
    } catch (e) {
      setError(e.message)
    } finally {
      setLoading(false)
      setRefreshing(false)
    }
  }, [workspaceId])

  useEffect(() => { load() }, [load])

  // ── No workspace selected ─────────────────────────────────────────────────
  if (!workspaceId) {
    return (
      <div className="max-w-screen-xl mx-auto px-6 py-8">
        <div className="card p-12 text-center">
          <div className="w-12 h-12 rounded-2xl bg-brand-50 flex items-center justify-center mx-auto mb-4">
            <Server className="w-6 h-6 text-brand-600" />
          </div>
          <h2 className="text-lg font-semibold text-gray-900 mb-2">Select a Workspace</h2>
          <p className="text-sm text-gray-400 mb-6">
            Asset inventory is scoped to a workspace. Select one from the top navigation.
          </p>
          <Link to="/workspaces" className="btn-primary">
            <ChevronRight className="w-4 h-4" />
            Go to Workspaces
          </Link>
        </div>
      </div>
    )
  }

  // ── Client-side filters ───────────────────────────────────────────────────
  const filtered = assets.filter(a => {
    if (statusFilter !== 'all' && a.status     !== statusFilter) return false
    if (typeFilter   !== 'all' && a.asset_type !== typeFilter)   return false
    return true
  })

  return (
    <div className="max-w-screen-xl mx-auto px-6 py-8 space-y-6">

      {/* Page header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2.5 mb-1">
            <div className="w-8 h-8 rounded-xl flex items-center justify-center" style={{ background: '#D6F0EC' }}>
              <Server className="w-4 h-4" style={{ color: '#12938C' }} />
            </div>
            <h1 className="text-2xl font-bold text-gray-900">Asset Inventory</h1>
          </div>
          <p className="text-sm text-gray-400 mt-0.5 ml-10">
            {workspaceName ? `Workspace: ${workspaceName}` : 'Persistent cross-scan asset tracking'}
          </p>
        </div>
        <button
          onClick={() => load(true)}
          disabled={refreshing || loading}
          className="btn-secondary flex-shrink-0"
        >
          <RefreshCw className={`w-4 h-4 ${refreshing ? 'animate-spin' : ''}`} />
          Refresh
        </button>
      </div>

      {/* Error */}
      {error && (
        <div className="px-4 py-3 bg-red-50 border border-red-100 rounded-xl text-sm text-red-700">
          <span className="font-semibold">Error:</span> {error}
        </div>
      )}

      {loading ? (
        <div className="flex items-center justify-center min-h-[40vh]">
          <Spinner size="lg" />
        </div>
      ) : (
        <>
          <ManagedCasesPanel workspaceId={workspaceId} />

          <AttackSurfaceAssurance
            presentations={assurance}
            coverage={assuranceCoverage}
          />

          {/* TEMPORARY integration mount of the reusable cross-domain CasesQueue.
              The Attack Surface page is NOT the permanent home for all-domain
              cases; the queue component is workspace-scoped and standalone, ready
              to move to its own route/nav in a later IA pass (not this episode). */}
          <div className="mt-4">
            <CasesQueue workspaceId={workspaceId} />
          </div>

          {/* ── Summary cards ─────────────────────────────────────────────── */}
          {summary && (
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-4">
              <StatCard icon={Layers}        label="Total assets"     explanation="Active inventory across this workspace" value={summary.total_assets} />
              <StatCard icon={Shield}        label="Legacy active"    explanation="Legacy inventory status; canonical observation is shown below" value={summary.active_assets} />
              <StatCard icon={Activity}      label="Legacy inactive"  explanation="Legacy inventory status; not confirmed removal" value={summary.inactive_assets} tone="neutral" />
              <StatCard icon={Server}        label="Subdomains"       explanation="Hostnames mapped under your domains"    value={summary.subdomains} tone="info" />
              <StatCard icon={Globe}         label="Exposed services" explanation="Internet-facing services to review"     value={summary.exposed_services} warning={(summary.exposed_services ?? 0) > 0} />
              <StatCard icon={Cloud}         label="Cloud assets"     explanation="Cloud storage and buckets found"        value={summary.cloud_storage_assets} tone="info" />
              <StatCard icon={AlertTriangle} label="Takeover risks"   explanation="Possible subdomain takeovers"           value={summary.takeover_risks} danger={(summary.takeover_risks ?? 0) > 0} />
            </div>
          )}

          {/* ── Filters ───────────────────────────────────────────────────── */}
          <div className="flex flex-wrap items-center gap-3">
            <div className="flex items-center gap-1.5">
              <span className="label">Status</span>
              {['all', 'active', 'inactive'].map(v => (
                <FilterBtn key={v} active={statusFilter === v} onClick={() => setStatusFilter(v)}>
                  {v === 'all' ? 'All' : v.charAt(0).toUpperCase() + v.slice(1)}
                </FilterBtn>
              ))}
            </div>

            <div className="w-px h-4 bg-gray-200" />

            <div className="flex items-center gap-1.5 flex-wrap">
              <span className="label">Type</span>
              {[
                { v: 'all',             label: 'All'             },
                { v: 'root_domain',     label: 'Root Domain'     },
                { v: 'subdomain',       label: 'Subdomain'       },
                { v: 'exposed_service', label: 'Exposed Service' },
                { v: 'cloud_storage',   label: 'Cloud Storage'   },
              ].map(({ v, label }) => (
                <FilterBtn key={v} active={typeFilter === v} onClick={() => setTypeFilter(v)}>
                  {label}
                </FilterBtn>
              ))}
            </div>

            <span className="ml-auto text-xs text-gray-400">
              {filtered.length} asset{filtered.length !== 1 ? 's' : ''}
            </span>
          </div>

          {/* ── Asset table ───────────────────────────────────────────────── */}
          <div className="card p-0 overflow-hidden">
            {filtered.length === 0 ? (
              <div className="text-center py-12 text-sm text-gray-400">
                No assets match the current filter.
              </div>
            ) : (
              <div className="overflow-x-auto">
                <table className="data-table w-full">
                  <thead>
                    <tr>
                      <th>Hostname</th>
                      <th>Type</th>
                      <th>Status</th>
                      <th>Source</th>
                      <th>Risk</th>
                      <th>Last Seen</th>
                      <th></th>
                    </tr>
                  </thead>
                  <tbody>
                    {filtered.map(asset => (
                      <tr
                        key={asset.id}
                        className="cursor-pointer hover:bg-brand-50/40 transition-colors"
                        onClick={() => setSelectedId(asset.id)}
                      >
                        <td>
                          <span className="mono text-xs font-medium text-gray-800">{asset.hostname}</span>
                          {asset.wildcard_dns === 1 && (
                            <span className="ml-2 text-[10px] text-amber-500 font-semibold">WILDCARD</span>
                          )}
                        </td>
                        <td><TypeBadge type={asset.asset_type} /></td>
                        <td><StatusPill status={asset.status} /></td>
                        <td className="text-xs text-gray-500">{asset.source || '—'}</td>
                        <td><RiskBadge level={asset.risk_level} /></td>
                        <td className="text-xs text-gray-500">{fmtDate(asset.last_seen)}</td>
                        <td className="pr-4">
                          <ChevronRight className="w-4 h-4 text-gray-300" />
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>

          {/* ── Timeline ──────────────────────────────────────────────────── */}
          <div className="card p-0 overflow-hidden">
            <div className="flex items-center gap-3 px-5 py-3 border-b border-gray-100">
              <div className="w-7 h-7 rounded-lg bg-brand-50 flex items-center justify-center flex-shrink-0">
                <Activity className="w-4 h-4 text-brand-600" />
              </div>
              <div className="flex items-baseline gap-2">
                <span className="text-sm font-semibold text-gray-900">Asset Timeline</span>
                <span className="text-xs text-gray-400">daily event counts · last 30 days</span>
              </div>
            </div>
            <Timeline rows={timeline} />
          </div>
        </>
      )}

      {/* ── Detail panel ────────────────────────────────────────────────────── */}
      {selectedId && (
        <AssetDetailPanel
          workspaceId={workspaceId}
          assetId={selectedId}
          onClose={() => setSelectedId(null)}
        />
      )}
    </div>
  )
}
