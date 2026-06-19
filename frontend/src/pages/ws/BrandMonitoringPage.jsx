import { useState, useEffect, useCallback } from 'react'
import { Globe, RefreshCw, CheckCircle, AlertCircle, Loader } from 'lucide-react'
import { useWorkspace } from '../../hooks/useWorkspace'
import { api } from '../../api'
import WsPage, { NoWorkspaceSelected } from '../../components/WsPage'
import RiskBadge from '../../components/RiskBadge'
import StatCard from '../../components/StatCard'
import DataTable from '../../components/DataTable'

const COLUMNS = [
  {
    key: 'candidate_domain',
    label: 'Candidate Domain',
    render: v => <span className="mono text-sm text-gray-900">{v}</span>,
  },
  {
    key: 'variant_type',
    label: 'Variant Type',
    render: v => <span className="text-xs text-gray-500 capitalize">{(v || '').replace(/_/g, ' ')}</span>,
  },
  { key: 'risk_level', label: 'Risk', render: v => <RiskBadge level={v} /> },
  {
    key: 'dns_resolves',
    label: 'DNS Active',
    render: v => v === 1
      ? <span className="flex items-center gap-1 text-xs font-semibold text-red-500"><AlertCircle className="w-3.5 h-3.5" />Resolves</span>
      : v === 0
        ? <span className="flex items-center gap-1 text-xs text-brand-600"><CheckCircle className="w-3.5 h-3.5" />No DNS</span>
        : <span className="text-xs text-gray-400">Unverified</span>,
  },
  {
    key: 'https_available',
    label: 'HTTPS',
    render: v => v === 1
      ? <span className="text-xs font-semibold text-red-500">Live Site</span>
      : v === 0
        ? <span className="text-xs text-gray-400">—</span>
        : <span className="text-xs text-gray-300">—</span>,
  },
  {
    key: 'status',
    label: 'Status',
    render: v => (
      <span className={`text-xs font-semibold capitalize ${
        v === 'active'     ? 'text-red-500'    :
        v === 'inactive'   ? 'text-gray-400'   :
                             'text-amber-500'
      }`}>{v}</span>
    ),
  },
  {
    key: 'risk_reasons',
    label: 'Risk Signals',
    render: v => {
      const reasons = typeof v === 'string' ? (() => { try { return JSON.parse(v) } catch { return [] } })() : (v || [])
      if (!reasons.length) return <span className="text-gray-300 text-xs">—</span>
      return (
        <div className="flex flex-wrap gap-1">
          {reasons.map((r, i) => (
            <span key={i} className="text-[10px] bg-gray-100 text-gray-600 px-1.5 py-0.5 rounded">{r}</span>
          ))}
        </div>
      )
    },
  },
]

export default function BrandMonitoringPage() {
  const { wsId, wsName } = useWorkspace()
  const [candidates, setCandidates] = useState([])
  const [summary, setSummary]       = useState(null)
  const [loading, setLoading]       = useState(true)
  const [error, setError]           = useState(null)
  const [validating, setValidating] = useState(false)
  const [validateMsg, setValidateMsg] = useState(null)
  const [filterRisk, setFilterRisk] = useState('')
  const [filterStatus, setFilterStatus] = useState('')

  const load = useCallback(async () => {
    if (!wsId) { setLoading(false); return }
    setLoading(true); setError(null)
    try {
      const params = {}
      if (filterRisk)   params.risk_level = filterRisk
      if (filterStatus) params.status     = filterStatus
      const [c, s] = await Promise.allSettled([
        api.getWorkspaceBrandMonitoring(wsId, params),
        api.getWorkspaceBrandMonitoringSummary(wsId),
      ])
      setCandidates(c.status === 'fulfilled' ? (c.value.candidates || []) : [])
      setSummary(s.status === 'fulfilled' ? s.value : null)
    } catch (e) {
      setError(e.message)
    } finally {
      setLoading(false)
    }
  }, [wsId, filterRisk, filterStatus])

  useEffect(() => { load() }, [load])

  const handleValidate = async () => {
    setValidating(true)
    setValidateMsg(null)
    try {
      const r = await api.refreshBrandMonitoring(wsId)
      setValidateMsg(r.message || `Validated ${r.checked ?? '?'} candidates`)
      await load()
    } catch (e) {
      setValidateMsg(`Error: ${e.message}`)
    } finally {
      setValidating(false)
    }
  }

  if (!wsId) return <NoWorkspaceSelected />

  const active    = candidates.filter(c => c.status === 'active').length
  const highRisk  = candidates.filter(c => ['high', 'critical'].includes(c.risk_level)).length
  const resolving = candidates.filter(c => c.dns_resolves === 1).length

  function FilterBtn({ value, current, onClick, children }) {
    return (
      <button
        onClick={onClick}
        className={current === value
          ? 'px-3 py-1.5 rounded-lg text-xs font-semibold bg-brand-600 text-white'
          : 'px-3 py-1.5 rounded-lg text-xs font-medium text-gray-500 hover:bg-gray-100 border border-gray-200'}
      >{children}</button>
    )
  }

  return (
    <WsPage wsId={wsId} wsName={wsName} loading={loading} error={error} onRetry={load}>
      <div className="flex items-start justify-between mb-6 gap-4 flex-wrap">
        <div>
          <h1 className="text-2xl font-bold text-gray-900">Brand Monitoring</h1>
          <p className="text-sm text-gray-400 mt-0.5">{wsName}</p>
        </div>
        <div className="flex items-center gap-3">
          {validateMsg && (
            <span className="text-xs text-gray-500 italic">{validateMsg}</span>
          )}
          <button
            onClick={handleValidate}
            disabled={validating}
            className="btn-primary flex items-center gap-2 disabled:opacity-60"
          >
            {validating
              ? <><Loader className="w-4 h-4 animate-spin" /> Validating…</>
              : <><RefreshCw className="w-4 h-4" /> Validate Now</>}
          </button>
        </div>
      </div>

      <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
        <StatCard icon={Globe} label="Candidates"    value={candidates.length} />
        <StatCard icon={Globe} label="Active (DNS)"  value={resolving} danger={resolving > 0} />
        <StatCard icon={Globe} label="High Risk"     value={highRisk}  danger={highRisk > 0} />
        <StatCard icon={Globe} label="Confirmed"     value={active}    danger={active > 0} />
      </div>

      {summary && (
        <div className="card p-5 mb-6">
          <h2 className="font-semibold text-gray-900 mb-3">Summary</h2>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            {summary.by_risk && Object.entries(summary.by_risk).map(([level, count]) => (
              <div key={level} className="flex items-center gap-2">
                <RiskBadge level={level} />
                <span className="text-sm font-semibold text-gray-700">{count}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Filters */}
      <div className="card p-4 mb-6 flex flex-wrap gap-2 items-center">
        <span className="text-xs text-gray-500 font-medium mr-1">Risk:</span>
        <FilterBtn value="" current={filterRisk} onClick={() => setFilterRisk('')}>All</FilterBtn>
        {['critical', 'high', 'medium', 'low'].map(r => (
          <FilterBtn key={r} value={r} current={filterRisk} onClick={() => setFilterRisk(r)}>
            <span className="capitalize">{r}</span>
          </FilterBtn>
        ))}

        <span className="text-xs text-gray-500 font-medium ml-4 mr-1">Status:</span>
        <FilterBtn value="" current={filterStatus} onClick={() => setFilterStatus('')}>All</FilterBtn>
        {['active', 'inactive', 'unverified'].map(s => (
          <FilterBtn key={s} value={s} current={filterStatus} onClick={() => setFilterStatus(s)}>
            <span className="capitalize">{s}</span>
          </FilterBtn>
        ))}
      </div>

      <div className="card overflow-hidden">
        <div className="px-5 py-4 border-b border-gray-100 flex items-center justify-between">
          <h2 className="font-semibold text-gray-900">Typosquat Candidates</h2>
          <span className="text-sm text-gray-400">{candidates.length} result{candidates.length !== 1 ? 's' : ''}</span>
        </div>
        <DataTable
          columns={COLUMNS}
          rows={candidates}
          empty={
            <div className="py-12 text-center">
              <Globe className="w-10 h-10 text-gray-200 mx-auto mb-3" />
              <p className="text-sm text-gray-400">No brand candidates yet.</p>
              <p className="text-xs text-gray-300 mt-1">Run a scan then click "Validate Now" to check lookalike domains.</p>
            </div>
          }
        />
      </div>
    </WsPage>
  )
}
