import { useState, useEffect, useCallback, useRef } from 'react'
import { useParams, Link, useNavigate } from 'react-router-dom'
import {
  RefreshCw, Briefcase, Globe, ScanLine, BarChart2,
  Plus, X, Trash2, ChevronLeft, Clock, Zap, CheckCircle,
  FileDown, Server, AlertTriangle, Cloud, Activity, Layers,
  ArrowRight, Shield,
} from 'lucide-react'
import { api } from '../api'
import Spinner from '../components/Spinner'
import ErrorAlert from '../components/ErrorAlert'
import StatusBadge from '../components/StatusBadge'

// ── Helpers ───────────────────────────────────────────────────────────────────

function isValidDomain(v) {
  return /^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/.test(
    (v || '').trim()
  )
}

function formatDate(str) {
  if (!str) return '—'
  const s = str.includes('T') ? str : str.replace(' ', 'T') + 'Z'
  return new Date(s).toLocaleString(undefined, {
    month: 'short', day: 'numeric',
    hour: '2-digit', minute: '2-digit',
  })
}

// ── Score Badge ───────────────────────────────────────────────────────────────

function ScoreBadge({ score, rating }) {
  if (score == null) {
    return <span className="text-xs text-gray-400 font-medium">—</span>
  }
  const cls =
    rating === 'excellent' || rating === 'good'
      ? 'bg-brand-50 text-brand-700 border-brand-100'
      : rating === 'moderate'
      ? 'bg-amber-50 text-amber-700 border-amber-100'
      : rating === 'high'
      ? 'bg-orange-50 text-orange-700 border-orange-100'
      : 'bg-red-50 text-red-700 border-red-100'
  return (
    <span className={`inline-flex items-center px-2 py-0.5 rounded-full text-xs font-bold border ${cls}`}>
      {score}
    </span>
  )
}

// ── Stat Card ─────────────────────────────────────────────────────────────────

function StatCard({ icon: Icon, label, value, sub, iconColor = 'text-brand-600', iconBg = 'bg-brand-50' }) {
  return (
    <div className="card p-5">
      <div className="flex items-start gap-3">
        <div className={`w-9 h-9 rounded-xl ${iconBg} flex items-center justify-center flex-shrink-0`}>
          <Icon className={`w-[18px] h-[18px] ${iconColor}`} />
        </div>
        <div>
          <p className="label">{label}</p>
          <p className="text-2xl font-bold text-gray-900 mt-1 leading-none">{value}</p>
          {sub && <p className="text-xs text-gray-400 mt-1">{sub}</p>}
        </div>
      </div>
    </div>
  )
}

// ── Add Domain Modal ──────────────────────────────────────────────────────────

function AddDomainModal({ workspaceId, onAdded, onClose }) {
  const [domain, setDomain]   = useState('')
  const [loading, setLoading] = useState(false)
  const [error, setError]     = useState(null)

  const valid = isValidDomain(domain)

  async function handleSubmit(e) {
    e.preventDefault()
    if (!valid) return
    setLoading(true)
    setError(null)
    try {
      const data = await api.addDomainToWorkspace(workspaceId, domain.trim().toLowerCase())
      onAdded(data.domain)
    } catch (err) {
      setError(err.message)
      setLoading(false)
    }
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
      <div className="absolute inset-0 bg-gray-900/40 backdrop-blur-sm" onClick={onClose} />
      <div className="relative bg-white rounded-2xl shadow-xl w-full max-w-md p-6 z-10">
        <div className="flex items-center justify-between mb-5">
          <h2 className="text-lg font-bold text-gray-900">Add Domain</h2>
          <button
            onClick={onClose}
            className="w-8 h-8 flex items-center justify-center rounded-lg text-gray-400 hover:text-gray-700 hover:bg-gray-100 transition-colors"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {error && (
          <div className="mb-4 p-3 bg-red-50 text-red-700 text-sm rounded-xl border border-red-100">
            {error}
          </div>
        )}

        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label className="label block mb-1.5">Domain</label>
            <div className="relative">
              <Globe className="absolute left-3.5 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-400 pointer-events-none" />
              <input
                className="input pl-10"
                placeholder="example.com"
                value={domain}
                onChange={e => setDomain(e.target.value)}
                autoFocus
                disabled={loading}
                spellCheck={false}
                autoCapitalize="none"
              />
            </div>
            {domain && !valid && (
              <p className="text-xs text-red-500 mt-1.5">Enter a valid domain (e.g. example.com)</p>
            )}
          </div>
          <div className="flex gap-3 pt-1">
            <button
              type="submit"
              disabled={!valid || loading}
              className="btn-primary flex-1 justify-center disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {loading ? 'Adding…' : 'Add Domain'}
            </button>
            <button type="button" onClick={onClose} className="btn-secondary">
              Cancel
            </button>
          </div>
        </form>
      </div>
    </div>
  )
}

// ── Main Page ─────────────────────────────────────────────────────────────────

export default function WorkspaceDetailPage() {
  const { id } = useParams()
  const navigate = useNavigate()

  const [workspace,    setWorkspace]    = useState(null)
  const [stats,        setStats]        = useState(null)
  const [domains,      setDomains]      = useState([])
  const [assetSummary, setAssetSummary] = useState(null)
  const [loading,      setLoading]      = useState(true)
  const [error,        setError]        = useState(null)
  const [refreshing,   setRefreshing]   = useState(false)
  const [showAdd,      setShowAdd]      = useState(false)

  // Per-domain scan state: { [domain]: 'idle' | 'scanning' | 'queued' }
  const [scanState, setScanState] = useState({})
  // Per-domain remove state
  const [removing, setRemoving]   = useState({})
  const [exporting, setExporting] = useState(false)
  const [exportError, setExportError] = useState(null)

  // Polling ref for active-scan auto-refresh
  const pollRef = useRef(null)

  const load = useCallback(async (silent = false) => {
    if (!silent) setLoading(true)
    else setRefreshing(true)
    setError(null)
    try {
      const [wsData, domainsData] = await Promise.all([
        api.getWorkspace(id),
        api.getWorkspaceDomains(id),
      ])
      setWorkspace(wsData.workspace)
      setStats(wsData.stats)
      setDomains(domainsData.domains || [])

      // Asset summary — fetch separately so a failure here never blocks the page
      api.getWorkspaceAssetsSummary(id)
        .then(d => setAssetSummary(d))
        .catch(() => { /* graceful — section stays hidden */ })
      // Keep workspace name in localStorage in sync
      if (wsData.workspace?.name) {
        localStorage.setItem('cybermeters_workspace_id', id)
        localStorage.setItem('cybermeters_workspace_name', wsData.workspace.name)
      }
    } catch (e) {
      setError(e.message)
    } finally {
      setLoading(false)
      setRefreshing(false)
    }
  }, [id])

  useEffect(() => { load() }, [load])

  // ── Active-scan auto-polling ─────────────────────────────────────────────────
  // If any domain has an active scan in progress, poll every 8 seconds so the
  // workspace page auto-refreshes without the user having to manually reload.
  // The interval is cleared as soon as all domains reach a terminal status.
  const ACTIVE_STATUSES = new Set(['queued', 'running', 'processing'])

  useEffect(() => {
    clearInterval(pollRef.current)
    const hasActive = domains.some(d => ACTIVE_STATUSES.has(d.latest_status))
    if (hasActive) {
      pollRef.current = setInterval(async () => {
        try {
          const domainsData = await api.getWorkspaceDomains(id)
          const updated = domainsData.domains || []
          setDomains(updated)
          // If no more active scans, clear the interval
          if (!updated.some(d => ACTIVE_STATUSES.has(d.latest_status))) {
            clearInterval(pollRef.current)
          }
        } catch { /* non-fatal — next tick will retry */ }
      }, 8_000)
    }
    return () => clearInterval(pollRef.current)
  }, [domains, id]) // eslint-disable-line react-hooks/exhaustive-deps

  // ── Scan Now ────────────────────────────────────────────────────────────────

  // ── Export PDF ──────────────────────────────────────────────────────────

  async function handleExportPdf() {
    setExporting(true)
    setExportError(null)
    try {
      const blob = await api.getWorkspaceReport(id)
      const url  = URL.createObjectURL(blob)
      const a    = document.createElement('a')
      a.href     = url
      a.download = `cybermeters-${(workspace?.name || id).replace(/[^a-z0-9]/gi, '-').toLowerCase()}-report.pdf`
      document.body.appendChild(a)
      a.click()
      document.body.removeChild(a)
      URL.revokeObjectURL(url)
    } catch (e) {
      setExportError(e.message)
    } finally {
      setExporting(false)
    }
  }

  // ── Scan Now ────────────────────────────────────────────────────────────

  async function handleScanNow(domain) {
    setScanState(s => ({ ...s, [domain]: 'scanning' }))
    try {
      await api.createScan(domain, id)
      setScanState(s => ({ ...s, [domain]: 'queued' }))
      // After 3s show idle again and silently refresh domain table
      setTimeout(async () => {
        setScanState(s => ({ ...s, [domain]: 'idle' }))
        await load(true)
      }, 3_000)
    } catch {
      setScanState(s => ({ ...s, [domain]: 'idle' }))
    }
  }

  // ── Remove Domain ───────────────────────────────────────────────────────────

  async function handleRemove(domainId, domainName) {
    setRemoving(r => ({ ...r, [domainId]: true }))
    try {
      await api.removeDomainFromWorkspace(id, domainId)
      setDomains(prev => prev.filter(d => d.domain_id !== domainId))
      setStats(prev => prev ? { ...prev, total_domains: Math.max(0, (prev.total_domains || 1) - 1) } : prev)
    } catch {
      // silently ignore — row stays
    } finally {
      setRemoving(r => ({ ...r, [domainId]: false }))
    }
  }

  // ── Add Domain ──────────────────────────────────────────────────────────────

  function handleAdded(newDomain) {
    // Prepend the new domain row optimistically
    setDomains(prev => [{
      domain_id:      newDomain.domain_id,
      domain:         newDomain.domain,
      last_scan_id:   null,
      latest_score:   null,
      latest_status:  null,
      last_scanned_at: null,
    }, ...prev])
    setStats(prev => prev ? { ...prev, total_domains: (prev.total_domains || 0) + 1 } : prev)
    setShowAdd(false)
  }

  // ── Render ──────────────────────────────────────────────────────────────────

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <Spinner />
      </div>
    )
  }

  if (error && !workspace) {
    return (
      <div className="max-w-screen-xl mx-auto px-6 py-8">
        <ErrorAlert message={error} />
      </div>
    )
  }

  const avgScore = stats?.cyber_score_average != null
    ? Math.round(stats.cyber_score_average)
    : null

  const avgRating =
    avgScore == null      ? null :
    avgScore >= 90        ? 'excellent' :
    avgScore >= 75        ? 'good'      :
    avgScore >= 50        ? 'moderate'  :
    avgScore >= 25        ? 'high'      : 'critical'

  return (
    <div className="max-w-screen-xl mx-auto px-6 py-8 space-y-6">

      {/* Back + header */}
      <div>
        <Link
          to="/workspaces"
          className="inline-flex items-center gap-1.5 text-sm text-gray-400 hover:text-gray-700 transition-colors mb-3"
        >
          <ChevronLeft className="w-4 h-4" />
          Workspaces
        </Link>
        <div className="flex items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-brand-50 flex items-center justify-center">
              <Briefcase className="w-5 h-5 text-brand-600" />
            </div>
            <div>
              <h1 className="text-2xl font-bold text-gray-900">{workspace?.name}</h1>
              <p className="text-xs text-gray-400 mt-0.5">Workspace ID: <span className="mono">{id}</span></p>
            </div>
          </div>
          <div className="flex items-center gap-2">
            <button onClick={() => load(true)} disabled={refreshing} className="btn-secondary">
              <RefreshCw className={`w-4 h-4 ${refreshing ? 'animate-spin' : ''}`} />
              Refresh
            </button>
            <button
              onClick={handleExportPdf}
              disabled={exporting}
              className="btn-secondary disabled:opacity-50 disabled:cursor-not-allowed"
              title="Download executive PDF report for this workspace"
            >
              {exporting
                ? <><RefreshCw className="w-4 h-4 animate-spin" />Generating…</>
                : <><FileDown className="w-4 h-4" />Export PDF</>
              }
            </button>
            <button onClick={() => setShowAdd(true)} className="btn-primary">
              <Plus className="w-4 h-4" />
              Add Domain
            </button>
          </div>
        </div>
      </div>

      {error && <ErrorAlert message={error} />}
      {exportError && (
        <div className="flex items-center gap-3 px-4 py-3 bg-red-50 border border-red-100 rounded-xl text-sm text-red-700">
          PDF export failed: {exportError}
        </div>
      )}

      {/* Stats cards */}
      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <StatCard
          icon={Globe}
          label="Total Domains"
          value={stats?.total_domains ?? 0}
          iconColor="text-brand-600"
          iconBg="bg-brand-50"
        />
        <StatCard
          icon={ScanLine}
          label="Total Scans"
          value={stats?.total_scans ?? 0}
          iconColor="text-blue-600"
          iconBg="bg-blue-50"
        />
        <StatCard
          icon={BarChart2}
          label="Avg Cyber Score"
          value={avgScore != null ? avgScore : '—'}
          sub={avgRating ? avgRating.charAt(0).toUpperCase() + avgRating.slice(1) : 'No completed scans'}
          iconColor="text-purple-600"
          iconBg="bg-purple-50"
        />
        <StatCard
          icon={Clock}
          label="Latest Scan"
          value={stats?.latest_scan ? stats.latest_scan.domain : '—'}
          sub={stats?.latest_scan ? formatDate(stats.latest_scan.created_at) : 'None yet'}
          iconColor="text-amber-600"
          iconBg="bg-amber-50"
        />
      </div>

      {/* Asset Inventory summary */}
      {assetSummary && (
        <div className="card p-5 space-y-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2.5">
              <div className="w-7 h-7 rounded-lg bg-brand-50 flex items-center justify-center flex-shrink-0">
                <Server className="w-4 h-4 text-brand-600" />
              </div>
              <span className="text-sm font-semibold text-gray-900">Asset Inventory</span>
            </div>
            <Link
              to="/assets"
              className="inline-flex items-center gap-1.5 text-xs font-semibold text-brand-600 hover:text-brand-700 transition-colors"
            >
              View Assets
              <ArrowRight className="w-3.5 h-3.5" />
            </Link>
          </div>
          <div className="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-7 gap-3">
            {[
              { icon: Layers,        label: 'Total',          value: assetSummary.total_assets,          ic: 'text-brand-600',  bg: 'bg-brand-50'  },
              { icon: Shield,        label: 'Active',         value: assetSummary.active_assets,         ic: 'text-green-600',  bg: 'bg-green-50'  },
              { icon: Activity,      label: 'Inactive',       value: assetSummary.inactive_assets,       ic: 'text-gray-400',   bg: 'bg-gray-100'  },
              { icon: Server,        label: 'Subdomains',     value: assetSummary.subdomains,            ic: 'text-blue-600',   bg: 'bg-blue-50'   },
              { icon: Globe,         label: 'Exposed',        value: assetSummary.exposed_services,      ic: 'text-amber-600',  bg: 'bg-amber-50'  },
              { icon: Cloud,         label: 'Cloud',          value: assetSummary.cloud_storage_assets,  ic: 'text-purple-600', bg: 'bg-purple-50' },
              { icon: AlertTriangle, label: 'Takeover Risks', value: assetSummary.takeover_risks,        ic: 'text-red-600',    bg: 'bg-red-50'    },
            ].map(({ icon: Icon, label, value, ic, bg }) => (
              <div key={label} className="flex items-center gap-2.5 px-3 py-2.5 rounded-xl bg-gray-50">
                <div className={`w-7 h-7 rounded-lg ${bg} flex items-center justify-center flex-shrink-0`}>
                  <Icon className={`w-3.5 h-3.5 ${ic}`} />
                </div>
                <div className="min-w-0">
                  <div className="text-lg font-bold text-gray-900 leading-none">{value ?? '—'}</div>
                  <div className="text-[10px] text-gray-400 mt-0.5 truncate">{label}</div>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Domains table */}
      <div className="card overflow-hidden">
        <div className="px-6 py-4 border-b border-gray-100 flex items-center justify-between">
          <div>
            <h2 className="font-semibold text-gray-900">Domains</h2>
            <p className="text-xs text-gray-400 mt-0.5">
              {domains.length} domain{domains.length !== 1 ? 's' : ''} in this workspace
            </p>
          </div>
          <button onClick={() => setShowAdd(true)} className="btn-ghost text-brand-600">
            <Plus className="w-3.5 h-3.5" />
            Add Domain
          </button>
        </div>

        {domains.length === 0 ? (
          <div className="px-6 py-12 flex flex-col items-center text-center">
            <div className="w-12 h-12 rounded-2xl bg-gray-50 flex items-center justify-center mb-3">
              <Globe className="w-6 h-6 text-gray-400" />
            </div>
            <h3 className="font-semibold text-gray-700 mb-1">No domains yet</h3>
            <p className="text-sm text-gray-400 mb-4">
              Add a domain to start tracking its security posture.
            </p>
            <button onClick={() => setShowAdd(true)} className="btn-secondary">
              <Plus className="w-4 h-4" />
              Add your first domain
            </button>
          </div>
        ) : (
          <table className="data-table">
            <thead>
              <tr>
                <th>Domain</th>
                <th>Score</th>
                <th>Status</th>
                <th>Last Scanned</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {domains.map(d => {
                const dState = scanState[d.domain] || 'idle'
                const isRemoving = removing[d.domain_id]
                return (
                  <tr key={d.domain_id}>
                    {/* Domain */}
                    <td>
                      <div className="flex items-center gap-2">
                        <Globe className="w-3.5 h-3.5 text-gray-400 flex-shrink-0" />
                        <span className="mono font-medium text-gray-900 text-sm">{d.domain}</span>
                      </div>
                    </td>

                    {/* Score */}
                    <td>
                      <ScoreBadge score={d.latest_score} rating={
                        d.latest_score == null ? null :
                        d.latest_score >= 90 ? 'excellent' :
                        d.latest_score >= 75 ? 'good'      :
                        d.latest_score >= 50 ? 'moderate'  :
                        d.latest_score >= 25 ? 'high'      : 'critical'
                      } />
                    </td>

                    {/* Status */}
                    <td>
                      {d.latest_status
                        ? <StatusBadge status={d.latest_status} />
                        : <span className="text-xs text-gray-400">Never scanned</span>
                      }
                    </td>

                    {/* Last scanned */}
                    <td>
                      <span className="text-sm text-gray-500">
                        {formatDate(d.last_scanned_at)}
                      </span>
                    </td>

                    {/* Actions */}
                    <td>
                      <div className="flex items-center gap-2 justify-end">
                        {/* Scan Now button */}
                        {dState === 'scanning' ? (
                          <span className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-blue-600 bg-blue-50 rounded-lg">
                            <RefreshCw className="w-3 h-3 animate-spin" />
                            Scanning…
                          </span>
                        ) : dState === 'queued' ? (
                          <span className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-brand-700 bg-brand-50 rounded-lg">
                            <CheckCircle className="w-3 h-3" />
                            Queued
                          </span>
                        ) : (
                          <button
                            onClick={() => handleScanNow(d.domain)}
                            className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold text-brand-700 bg-brand-50 hover:bg-brand-100 rounded-lg transition-colors"
                          >
                            <Zap className="w-3 h-3" />
                            Scan Now
                          </button>
                        )}

                        {/* View scan report if available */}
                        {d.last_scan_id && (
                          <Link
                            to={`/scans/${d.last_scan_id}`}
                            className="inline-flex items-center gap-1 px-2.5 py-1.5 text-xs font-medium text-gray-500 hover:text-gray-900 hover:bg-gray-100 rounded-lg transition-colors"
                          >
                            View report
                          </Link>
                        )}

                        {/* Remove */}
                        <button
                          onClick={() => handleRemove(d.domain_id, d.domain)}
                          disabled={isRemoving}
                          className="w-7 h-7 flex items-center justify-center rounded-lg text-gray-300 hover:text-red-500 hover:bg-red-50 transition-colors disabled:opacity-40"
                          title="Remove from workspace"
                        >
                          <Trash2 className="w-3.5 h-3.5" />
                        </button>
                      </div>
                    </td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        )}
      </div>

      {/* Add Domain modal */}
      {showAdd && (
        <AddDomainModal
          workspaceId={id}
          onAdded={handleAdded}
          onClose={() => setShowAdd(false)}
        />
      )}
    </div>
  )
}
